"""Anchor collector: snapshot the current Entra identity graph via Microsoft Graph (read-only).

python -m itm.collect --out anchor.json [--tenant <id>] [--auth cli|sdk] [--all-sp-owners]

Auth
  cli  token from `az account get-access-token --resource-type ms-graph` (default, no extra packages)
  sdk  azure-identity DefaultAzureCredential (env vars, managed identity, etc.)

Permissions (read-only). Delegated via az CLI needs a signed-in user with at least Global Reader.
If role endpoints return 403 with the az CLI token, use an app registration with the application
permissions User.Read.All, GroupMember.Read.All, Application.Read.All, RoleManagement.Read.Directory
and run with --auth sdk (AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET).

The snapshot is not atomic. captured_at is the START of collection. Changes made while the
collector runs may show up as conflicts in `itm summary`. Keep runs short and off-peak.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import quote

from .model import BACKS, CREDENTIAL, HAS_ROLE, MEMBER_OF, OWNS, fmt_time, key_node, role_node

GRAPH = "https://graph.microsoft.com/v1.0"
BATCH_SIZE = 20
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}
ODATA_TYPES = {"#microsoft.graph.user": "User", "#microsoft.graph.group": "Group",
               "#microsoft.graph.servicePrincipal": "ServicePrincipal"}


class GraphError(Exception):
    pass


# transport and auth

def urllib_transport(method, url, headers, body):
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()


def cli_token(tenant=None) -> str:
    az = shutil.which("az")  # resolves az.cmd on Windows
    if not az:
        raise GraphError("az CLI not found on PATH")
    cmd = [az, "account", "get-access-token", "--resource-type", "ms-graph", "--query", "accessToken", "-o", "tsv"]
    if tenant:
        cmd += ["--tenant", tenant]
    return subprocess.check_output(cmd, text=True).strip()


def sdk_token(tenant=None) -> str:
    from azure.identity import DefaultAzureCredential  # optional dependency
    kw = {"tenant_id": tenant} if tenant else {}
    return DefaultAzureCredential().get_token("https://graph.microsoft.com/.default", **kw).token


def _retry_after(headers, attempt) -> float:
    for k, v in (headers or {}).items():
        if k.lower() == "retry-after":
            try:
                return float(v)
            except ValueError:
                break
    return float(min(2 ** attempt, 60))


class GraphClient:
    def __init__(self, token_provider, transport=urllib_transport, base=GRAPH,
                 max_retries=6, sleep=time.sleep):
        self.token_provider, self.transport, self.base = token_provider, transport, base
        self.max_retries, self.sleep = max_retries, sleep
        self._token = None
        self.calls = self.throttled = self.token_refreshes = 0

    def _headers(self):
        if self._token is None:
            self._token = self.token_provider()
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json",
                "Accept": "application/json"}

    def request(self, method, url, payload=None) -> dict:
        if not url.startswith("http"):
            url = self.base + url
        body = json.dumps(payload).encode() if payload is not None else None
        refreshed = False
        for attempt in range(self.max_retries + 1):
            self.calls += 1
            status, headers, raw = self.transport(method, url, self._headers(), body)
            if status == 401 and not refreshed:
                self._token, refreshed = None, True
                self.token_refreshes += 1
                continue
            if status in (429, 503, 504):
                self.throttled += 1
                self.sleep(_retry_after(headers, attempt))
                continue
            data = json.loads(raw) if raw else {}
            if status >= 400:
                msg = (data.get("error") or {}).get("message") if isinstance(data, dict) else raw[:200]
                raise GraphError(f"{method} {url} -> {status}: {msg}")
            return data
        raise GraphError(f"{method} {url}: retries exhausted")

    def get_all(self, url) -> list:
        out = []
        while url:
            d = self.request("GET", url)
            out += d.get("value", [])
            url = d.get("@odata.nextLink")
        return out

    def batch_get_all(self, urls) -> tuple:
        """GET many relative URLs through $batch. Returns ({url: [items]}, {url: error})."""
        results, errors = {}, {}
        pending, attempt = list(urls), 0
        while pending:
            retry = []
            for i in range(0, len(pending), BATCH_SIZE):
                chunk = pending[i:i + BATCH_SIZE]
                reqs = [{"id": str(n), "method": "GET", "url": u} for n, u in enumerate(chunk)]
                resp = self.request("POST", "/$batch", {"requests": reqs})
                for r in resp.get("responses", []):
                    u, st, b = chunk[int(r["id"])], r.get("status"), r.get("body") or {}
                    if st == 200:
                        vals = list(b.get("value", []))
                        if b.get("@odata.nextLink"):
                            vals += self.get_all(b["@odata.nextLink"])
                        results[u] = vals
                    elif st in (429, 503, 504):
                        retry.append(u)
                    else:
                        errors[u] = f"{st}: {(b.get('error') or {}).get('message', '')}"
            if retry:
                attempt += 1
                self.throttled += len(retry)
                if attempt > self.max_retries:
                    errors.update({u: "throttled, retries exhausted" for u in retry})
                    break
                self.sleep(float(min(2 ** attempt, 30)))
            pending = retry
        return results, errors


# collection

def collect(client: GraphClient, all_sp_owners=False, clock=None, log=lambda m: None) -> dict:
    now = clock or (lambda: datetime.now(timezone.utc))
    started = now()
    warnings = []

    log("organization")
    org = client.get_all("/organization?$select=id")
    tenant_id = org[0]["id"].lower() if org else None
    log("users")
    users = client.get_all("/users?$select=id,displayName,userPrincipalName&$top=999")
    log("groups")
    groups = client.get_all("/groups?$select=id,displayName,isAssignableToRole&$top=999")
    log("applications")
    apps = client.get_all("/applications?$select=id,appId,displayName,keyCredentials,passwordCredentials&$top=999")
    log("service principals")
    sps = client.get_all("/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,"
                         "appOwnerOrganizationId,keyCredentials,passwordCredentials&$top=999")
    log("role definitions and assignments")
    roledefs = client.get_all("/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn")
    assignments = client.get_all("/roleManagement/directory/roleAssignments?"
                                 "$select=id,principalId,roleDefinitionId,directoryScopeId")
    # Also query each role definition and union the results, rather than relying on one listing.
    seen = {ra["id"] for ra in assignments}
    per_role = [f"/roleManagement/directory/roleAssignments?$filter="
                f"{quote(chr(39).join(['roleDefinitionId eq ', d['id'], '']), safe=chr(39))}"
                f"&$select=id,principalId,roleDefinitionId,directoryScopeId" for d in roledefs]
    log(f"role assignments per role ({len(per_role)} role definitions)")
    res, errs = client.batch_get_all(per_role)
    per_role_only = []
    for u in per_role:
        for ra in res.get(u, []):
            if ra["id"] not in seen:
                seen.add(ra["id"])
                assignments.append(ra)
                per_role_only.append({"principalId": ra["principalId"], "roleDefinitionId": ra["roleDefinitionId"],
                                      "directoryScopeId": ra.get("directoryScopeId")})
    per_role_errors = [f"per-role assignments {u}: {e}" for u, e in errs.items()]

    objects, edges = {}, set()
    for u in users:
        objects[u["id"].lower()] = {"type": "User", "displayName": u.get("displayName"),
                                    "userPrincipalName": u.get("userPrincipalName")}
    for g in groups:
        objects[g["id"].lower()] = {"type": "Group", "displayName": g.get("displayName"),
                                    "isAssignableToRole": g.get("isAssignableToRole")}
    for a in apps:
        objects[a["id"].lower()] = {"type": "Application", "displayName": a.get("displayName"), "appId": a.get("appId")}
    for s in sps:
        objects[s["id"].lower()] = {"type": "ServicePrincipal", "displayName": s.get("displayName"),
                                    "appId": s.get("appId"), "servicePrincipalType": s.get("servicePrincipalType"),
                                    "appOwnerOrganizationId": s.get("appOwnerOrganizationId")}

    # roles: node id is role:<templateId> so it matches Role.TemplateId in AuditLogs
    tmpl = {}
    for d in roledefs:
        t = (d.get("templateId") or d["id"]).lower()
        tmpl[d["id"].lower()] = t
        objects[role_node(t)] = {"type": "DirectoryRole", "displayName": d.get("displayName"),
                                 "isBuiltIn": d.get("isBuiltIn")}
    scoped, foreign_assignments, foreign = 0, 0, set()
    for ra in assignments:
        if (ra.get("directoryScopeId") or "/") != "/":
            scoped += 1
            continue
        rid = ra["roleDefinitionId"].lower()
        pid = ra["principalId"].lower()
        if pid not in objects or objects[pid]["type"] == "ForeignPrincipal":
            foreign_assignments += 1
            foreign.add(pid)
            objects[pid] = {"type": "ForeignPrincipal", "displayName": None}
        edges.add((HAS_ROLE, pid, role_node(tmpl.get(rid, rid))))

    # app registration -> its service principal
    sp_by_appid = {s["appId"].lower(): s["id"].lower() for s in sps if s.get("appId")}
    for a in apps:
        sp = sp_by_appid.get((a.get("appId") or "").lower())
        if sp:
            edges.add((BACKS, a["id"].lower(), sp))

    # credentials on apps and SPs
    for obj in apps + sps:
        for c in (obj.get("passwordCredentials") or []) + (obj.get("keyCredentials") or []):
            if c.get("keyId"):
                edges.add((CREDENTIAL, key_node(c["keyId"]), obj["id"].lower()))

    # direct group members
    log(f"members of {len(groups)} groups")
    member_urls = {f"/groups/{g['id']}/members?$select=id&$top=999": g["id"].lower() for g in groups}
    res, errs = client.batch_get_all(list(member_urls))
    skipped_member_types = Counter()
    for u, gid in member_urls.items():
        for m in res.get(u, []):
            typ = ODATA_TYPES.get(m.get("@odata.type"))
            if typ is None:
                skipped_member_types[m.get("@odata.type") or "unknown"] += 1
                continue
            edges.add((MEMBER_OF, m["id"].lower(), gid))
    warnings += [f"members {u}: {e}" for u, e in errs.items()]

    # owners of apps and tenant-owned SPs (first-party Microsoft SPs skipped unless asked)
    owner_sps = [s for s in sps if all_sp_owners
                 or (s.get("appOwnerOrganizationId") or "").lower() not in MICROSOFT_TENANTS]
    owner_urls = {f"/applications/{a['id']}/owners?$select=id": a["id"].lower() for a in apps}
    owner_urls.update({f"/servicePrincipals/{s['id']}/owners?$select=id": s["id"].lower() for s in owner_sps})
    log(f"owners of {len(apps)} apps and {len(owner_sps)} service principals")
    res, errs = client.batch_get_all(list(owner_urls))
    for u, oid in owner_urls.items():
        for o in res.get(u, []):
            if ODATA_TYPES.get(o.get("@odata.type")) in ("User", "ServicePrincipal"):
                edges.add((OWNS, o["id"].lower(), oid))
    warnings += [f"owners {u}: {e}" for u, e in errs.items()]

    warnings += per_role_errors
    if per_role_only:
        warnings.append(f"{len(per_role_only)} role assignments found only via per-role queries "
                        f"(see collection.per_role_only)")
    if scoped:
        warnings.append(f"{scoped} scoped role assignments skipped (directoryScopeId != '/')")
    if foreign:
        warnings.append(f"{foreign_assignments} role assignments held by {len(foreign)} principals outside this "
                        f"directory (typed ForeignPrincipal)")

    finished = now()
    counts = Counter(e[0] for e in edges)
    return {
        "captured_at": fmt_time(started),
        "tenant_id": tenant_id,
        "objects": objects,
        "edges": [{"type": t, "src": s, "dst": d} for t, s, d in sorted(edges)],
        "collection": {
            "started_at": fmt_time(started), "finished_at": fmt_time(finished),
            "duration_seconds": round((finished - started).total_seconds(), 1),
            "object_counts": dict(Counter(o["type"] for o in objects.values())),
            "edge_counts": dict(counts),
            "skipped_member_types": dict(skipped_member_types),
            "graph_calls": client.calls, "throttled": client.throttled,
            "token_refreshes": client.token_refreshes, "warnings": warnings,
            "per_role_only": per_role_only,
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="itm.collect", description="Snapshot the Entra identity graph (read-only)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--tenant")
    ap.add_argument("--auth", choices=["cli", "sdk"], default="cli")
    ap.add_argument("--all-sp-owners", action="store_true", help="also query owners of Microsoft first-party SPs")
    a = ap.parse_args(argv)

    provider = (lambda: cli_token(a.tenant)) if a.auth == "cli" else (lambda: sdk_token(a.tenant))
    client = GraphClient(provider)
    anchor = collect(client, all_sp_owners=a.all_sp_owners, log=lambda m: print(f"[collect] {m}", file=sys.stderr))
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(anchor, fh, indent=1)
    c = anchor["collection"]
    print(f"captured_at {anchor['captured_at']}  duration {c['duration_seconds']}s  calls {c['graph_calls']}  "
          f"throttled {c['throttled']}")
    print("objects", c["object_counts"])
    print("edges  ", c["edge_counts"])
    for w in c["warnings"]:
        print("WARN", w)


if __name__ == "__main__":
    main()
