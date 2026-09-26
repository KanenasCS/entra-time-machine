"""Fake Microsoft Graph serving the synthetic tenant at the anchor time.

Exercises what breaks collectors in real life: small pages with nextLink, 429 on a direct call,
429 on an item inside a $batch, an expired first token, non-actor group members (devices),
scoped role assignments, and Microsoft first-party SPs whose owners must not be queried.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from urllib.parse import parse_qs, urlsplit

from generate import ANCHOR, ROLES, build, gid, truth_state

GRAPH = "https://graph.microsoft.com/v1.0"
MS_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
EXPIRED = "expired-token"


class FakeGraph:
    def __init__(self, page_size=3):
        self.page_size = page_size
        self.calls = Counter()
        self.forbidden_hits = []
        self._throttled_once = set()

        s, ivs = build()
        state = truth_state(ivs, ANCHOR)
        deleted = {json.loads(r["TargetResources"])[0]["id"] for r in s.rows if r["OperationName"] == "Delete user"}
        objs = {k: v for k, v in s.objects.items() if k not in deleted and not v.get("foreign")}
        tenant = gid("tenant")

        d = self.data = {}
        d["/users"] = [{"id": i, "displayName": o["displayName"], "userPrincipalName": o["userPrincipalName"]}
                       for i, o in objs.items() if o["type"] == "User"]
        d["/groups"] = [{"id": i, "displayName": o["displayName"], "isAssignableToRole": o["displayName"] == "IT-Admins"}
                        for i, o in objs.items() if o["type"] == "Group"]

        def creds(obj_id):
            return [{"keyId": k, "displayName": n} for k, n in s.app_keys.get(obj_id, [])]

        d["/applications"] = [{"id": i, "appId": o["appId"], "displayName": o["displayName"],
                               "passwordCredentials": creds(i), "keyCredentials": []}
                              for i, o in objs.items() if o["type"] == "Application"]
        sps = [{"id": i, "appId": o["appId"], "displayName": o["displayName"], "servicePrincipalType": "Application",
                "appOwnerOrganizationId": tenant, "passwordCredentials": creds(i), "keyCredentials": []}
               for i, o in objs.items() if o["type"] == "ServicePrincipal"]
        self.first_party_sp = gid("sp:Microsoft Graph")
        sps.append({"id": self.first_party_sp, "appId": "00000003-0000-0000-c000-000000000000",
                    "displayName": "Microsoft Graph", "servicePrincipalType": "Application",
                    "appOwnerOrganizationId": MS_TENANT, "passwordCredentials": [], "keyCredentials": []})
        d["/servicePrincipals"] = sps

        d["/roleManagement/directory/roleDefinitions"] = [
            {"id": t, "templateId": t, "displayName": n, "isBuiltIn": True} for n, t in ROLES.items()]
        all_state_ras = [{"id": f"ra{n}", "principalId": e[1], "roleDefinitionId": e[2][5:], "directoryScopeId": "/"}
                         for n, e in enumerate(sorted(e for e in state if e[0] == "has_role"))]
        ras = [r for r in all_state_ras if r["principalId"] in objs]           # unfiltered listing: local principals only (test scenario)
        foreign_state_ras = [r for r in all_state_ras if r["principalId"] not in objs]
        ras.append({"id": "ra-scoped", "principalId": gid("user:judy"),
                    "roleDefinitionId": ROLES["Helpdesk Administrator"],
                    "directoryScopeId": "/administrativeUnits/" + gid("au:EMEA")})
        self.foreign_group = gid("foreign:governing-tenant-group")
        self.foreign_ra = {"id": "ra-foreign", "principalId": self.foreign_group,
                           "roleDefinitionId": ROLES["Helpdesk Administrator"], "directoryScopeId": "/"}
        d["/roleManagement/directory/roleAssignments"] = ras  # unfiltered listing: local principals only (test scenario)
        self.all_ras = ras + foreign_state_ras + [self.foreign_ra]
        d["/organization"] = [{"id": tenant}]

        type_of = lambda i: "#microsoft.graph." + {"User": "user", "Group": "group",  # noqa: E731
                                                   "ServicePrincipal": "servicePrincipal"}[s.objects[i]["type"]]
        members, owners = defaultdict(list), defaultdict(list)
        for e in state:
            if e[0] == "member_of":
                members[e[2]].append({"@odata.type": type_of(e[1]), "id": e[1]})
            elif e[0] == "owns":
                owners[e[2]].append({"@odata.type": type_of(e[1]), "id": e[1]})
        members[gid("group:All-Staff")].append({"@odata.type": "#microsoft.graph.device", "id": gid("device:kiosk")})
        for g in d["/groups"]:
            d[f"/groups/{g['id']}/members"] = members.get(g["id"], [])
        for a in d["/applications"]:
            d[f"/applications/{a['id']}/owners"] = owners.get(a["id"], [])
        for sp in sps:
            d[f"/servicePrincipals/{sp['id']}/owners"] = owners.get(sp["id"], [])
        self.first_group_members = f"/groups/{d['/groups'][0]['id']}/members"

    # routing
    def _page(self, path, query):
        if path not in self.data:
            return 404, {}, {"error": {"code": "Request_ResourceNotFound", "message": path}}
        if path == f"/servicePrincipals/{self.first_party_sp}/owners":
            self.forbidden_hits.append(path)
        source = self.data[path]
        flt = (query.get("$filter") or [None])[0]
        if flt and path == "/roleManagement/directory/roleAssignments":
            rid = flt.split("'")[1]
            source = [r for r in self.all_ras if r["roleDefinitionId"] == rid]
        skip = int(query.get("$skiptoken", ["0"])[0])
        items = source[skip:skip + self.page_size]
        body = {"value": items}
        if skip + self.page_size < len(source):
            nl = f"{GRAPH}{path}?$skiptoken={skip + self.page_size}"
            if flt:
                nl += "&$filter=" + flt.replace(" ", "%20")
            body["@odata.nextLink"] = nl
        return 200, {}, body

    def _serve(self, url, in_batch):
        parts = urlsplit(url)
        path = parts.path[len("/v1.0"):] if parts.path.startswith("/v1.0") else parts.path
        query = parse_qs(parts.query)
        self.calls[path] += 1
        once_key = ("batch" if in_batch else "direct", path)
        if (path == "/users" and not in_batch) or (path == self.first_group_members and in_batch):
            if once_key not in self._throttled_once:
                self._throttled_once.add(once_key)
                return 429, {"Retry-After": "0"}, {"error": {"code": "TooManyRequests", "message": "slow down"}}
        return self._page(path, query)

    def transport(self, method, url, headers, body):
        if headers.get("Authorization") == f"Bearer {EXPIRED}":
            return 401, {}, json.dumps({"error": {"code": "InvalidAuthenticationToken", "message": "expired"}}).encode()
        if method == "POST" and url.endswith("/$batch"):
            reqs = json.loads(body)["requests"]
            assert len(reqs) <= 20, "Graph rejects batches over 20"
            out = []
            for r in reqs:
                st, hd, b = self._serve(r["url"], in_batch=True)
                out.append({"id": r["id"], "status": st, "headers": hd, "body": b})
            return 200, {}, json.dumps({"responses": out}).encode()
        st, hd, b = self._serve(url, in_batch=False)
        return st, hd, json.dumps(b).encode()
