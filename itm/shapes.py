"""Shape report: validate parser assumptions against a real AuditLogs export.

python -m itm.shapes auditlogs.json [--samples 1]

Prints, per operation, the structure of the rows (target type order, modifiedProperty names,
AdditionalDetails keys, initiator kind) and whether the parser produced deltas. GUIDs, UPNs,
IPs and display names are redacted, so the output can be shared for troubleshooting.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict

from .parse import EXPIRY_KEYS, _j, _norm_op, load_rows, parse_rows

GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
DISPLAY = re.compile(r"(DisplayName=)[^,\]]*")


def redact(text: str) -> str:
    text = GUID.sub("<guid>", text)
    text = EMAIL.sub("<upn>", text)
    text = IP.sub("<ip>", text)
    return DISPLAY.sub(r"\1<name>", text)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="itm.shapes")
    ap.add_argument("logs")
    ap.add_argument("--samples", type=int, default=1, help="redacted modifiedProperties samples per operation")
    a = ap.parse_args(argv)

    rows = load_rows(a.logs)
    by_op = defaultdict(list)
    for r in rows:
        by_op[r.get("OperationName") or ""].append(r)

    print(f"rows {len(rows)}   operations {len(by_op)}\n")
    pim_pairing(rows)
    app_role_readout(rows)
    for op, rs in sorted(by_op.items(), key=lambda x: -len(x[1])):
        parsed = parse_rows(rs)
        results = Counter(r.get("Result") for r in rs)
        orders, props, details, inits = Counter(), defaultdict(Counter), Counter(), Counter()
        samples = []
        for r in rs:
            targets = _j(r.get("TargetResources")) or []
            orders[" > ".join(t.get("type") or "?" for t in targets)] += 1
            for i, t in enumerate(targets):
                for p in t.get("modifiedProperties") or []:
                    props[i][p.get("displayName")] += 1
                    if p.get("displayName") == "KeyDescription" and len(samples) < a.samples:
                        samples.append(redact(f"old={p.get('oldValue')} new={p.get('newValue')}"))
            for d in _j(r.get("AdditionalDetails")) or []:
                details[d.get("key")] += 1
            ib = _j(r.get("InitiatedBy")) or {}
            inits["user" if ib.get("user") else "app" if ib.get("app") else "none"] += 1

        success = results.get("success", 0)
        handled = parsed.deltas or parsed.deletions
        ignored = any(k.startswith("ignored duplicate") for k in parsed.skipped)
        verdict = ("ignored, see PIM PAIRING" if ignored else
                   "OK" if handled and not parsed.errors else
                   "ERRORS" if parsed.errors else
                   "not handled" if success else "no successful rows")
        print(f"== {op}  [{verdict}]")
        print(f"   rows {len(rs)}  results {dict(results)}  initiator {dict(inits)}")
        print(f"   deltas {len(parsed.deltas)}  deletions {len(parsed.deletions)}  errors {len(parsed.errors)}")
        for o, n in orders.most_common(3):
            print(f"   targets: {o}  ({n})")
        for i in sorted(props):
            print(f"   target[{i}] modifiedProperties: {', '.join(k for k, _ in props[i].most_common(8))}")
        if details:
            print(f"   AdditionalDetails keys: {', '.join(k for k, _ in details.most_common(10))}")
        if "pim activation" in _norm_op(op) and op.lower().startswith("add"):
            found = [k for k in details if (k or "").lower() in EXPIRY_KEYS]
            print(f"   PIM expiry key recognised: {found or 'NONE (engine will use default duration)'}")
        for s in samples:
            print(f"   KeyDescription sample: {s[:300]}")
        for e in parsed.errors[:3]:
            print(f"   error: {redact(e)}")
        print()


def pim_pairing(rows):
    """Pair 'outside of PIM' role adds with Core Directory 'Add member to role' by principal and role."""
    import hashlib
    from datetime import timedelta
    core_rows = [r for r in rows if _norm_op(r.get("OperationName") or "") == "add member to role"]
    pim_rows = [r for r in rows if _norm_op(r.get("OperationName") or "").startswith("add member to role outside of pim")]
    if not pim_rows:
        return
    as_core = [dict(r, OperationName="Add member to role") for r in pim_rows]
    core = parse_rows(core_rows).deltas
    pim_p = parse_rows(as_core)
    pim = pim_p.deltas
    h = lambda x: hashlib.sha256(x.encode()).hexdigest()[:8]  # noqa: E731
    names = parse_rows(core_rows + as_core).objects_seen

    print("== PIM PAIRING: 'outside of PIM' vs Core Directory 'Add member to role'")
    print(f"   outside-of-PIM parsed {len(pim)} of {len(pim_rows)} rows ({len(pim_p.errors)} errors)   core adds {len(core)}")
    used = set()
    buckets = {"<=1m": 0, "<=1h": 0, "<=24h": 0, ">24h": 0, "none": 0}
    for p in sorted(pim, key=lambda d: d.time):
        cands = [(abs((p.time - c.time).total_seconds()), i, c) for i, c in enumerate(core)
                 if c.edge == p.edge and i not in used]
        role = (names.get(p.edge.dst) or {}).get("displayName") or p.edge.dst
        ptype = (names.get(p.edge.src) or {}).get("type") or "?"
        if cands:
            secs, i, c = min(cands)
            used.add(i)
            lag = (p.time - c.time).total_seconds() / 60
            b = "<=1m" if secs <= 60 else "<=1h" if secs <= 3600 else "<=24h" if secs <= 86400 else ">24h"
            buckets[b] += 1
            print(f"   {p.time:%Y-%m-%d %H:%M}  {ptype:<16} {h(p.edge.src)}  {role:<40} core match, PIM lag {lag:+.0f} min")
        else:
            buckets["none"] += 1
            print(f"   {p.time:%Y-%m-%d %H:%M}  {ptype:<16} {h(p.edge.src)}  {role:<40} NO core event")
    for i, c in enumerate(core):
        if i not in used:
            role = (names.get(c.edge.dst) or {}).get("displayName") or c.edge.dst
            ptype = (names.get(c.edge.src) or {}).get("type") or "?"
            print(f"   {c.time:%Y-%m-%d %H:%M}  {ptype:<16} {h(c.edge.src)}  {role:<40} core only, no PIM event")
    print(f"   match distance: {buckets}")
    print()


def app_role_readout(rows):
    """Structure and risk readout for 'Add app role assignment to service principal' (no PII)."""
    from .model import GRAPH_APP_ID, TIER0_GRAPH_APP_ROLES
    rs = [r for r in rows if _norm_op(r.get("OperationName") or "") == "add app role assignment to service principal"
          and (r.get("Result") or "").lower() == "success"]
    if not rs:
        return
    perms, match_idx, graph_side, flagged = Counter(), Counter(), Counter(), Counter()
    for r in rs:
        t = _j(r.get("TargetResources")) or []
        if not t:
            continue
        mp = {p.get("displayName"): (_j(p.get("newValue")) if p.get("newValue") else None)
              for p in t[0].get("modifiedProperties") or []}
        clean = lambda v: v.strip().strip('"') if isinstance(v, str) else v  # noqa: E731
        value = clean(mp.get("AppRole.Value")) or "(none)"
        sp_obj = (clean(mp.get("ServicePrincipal.ObjectID")) or "").lower()
        sp_app = (clean(mp.get("ServicePrincipal.AppId")) or "").lower()
        idx = [i for i, x in enumerate(t) if (x.get("id") or "").lower() == sp_obj]
        match_idx[f"ServicePrincipal.ObjectID == target{idx}"] += 1
        graph_side["ServicePrincipal.AppId is Microsoft Graph" if sp_app == GRAPH_APP_ID else
                   "ServicePrincipal.AppId is NOT Microsoft Graph"] += 1
        perms[value] += 1
        if value in TIER0_GRAPH_APP_ROLES:
            flagged[value] += 1
    print("== APP ROLE ASSIGNMENTS: structure and risk (permission names only)")
    print(f"   rows {len(rs)}")
    for k, v in match_idx.most_common():
        print(f"   {k}: {v}")
    for k, v in graph_side.most_common():
        print(f"   {k}: {v}")
    print(f"   distinct permissions {len(perms)}. Top: " + ", ".join(f"{k} ({v})" for k, v in perms.most_common(12)))
    if flagged:
        print("   TIER-0 EQUIVALENT grants in window: " + ", ".join(f"{k} ({v})" for k, v in flagged.most_common()))
    else:
        print("   no tier-0 equivalent Graph permissions granted in window")
    print()


if __name__ == "__main__":
    main()
