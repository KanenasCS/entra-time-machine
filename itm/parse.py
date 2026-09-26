"""Turn Entra AuditLogs rows (Log Analytics shape) into edge deltas.

Accepts a JSON array or JSONL. Dynamic columns (InitiatedBy, TargetResources,
AdditionalDetails) may be objects or JSON-encoded strings, since az CLI exports
return them as strings.

Field layouts are based on documented and commonly observed AuditLogs shapes.
VALIDATE AGAINST A REAL TENANT before trusting results. Every parse decision is
isolated in one handler per operation so fixes stay local.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field

from .model import (CREDENTIAL, HAS_ROLE, MEMBER_OF, OWNS, Delta, EdgeKey,
                    ObjectDeletion, key_node, parse_time, role_node)

PRINCIPAL_TYPES = {"User", "Group", "ServicePrincipal"}
_KEYID = re.compile(r"KeyIdentifier=([0-9a-fA-F-]{8,})")
EXPIRY_KEYS = {"expirationtime", "expirationdatetime", "enddatetime", "endtime"}


@dataclass
class ParsedLog:
    deltas: list = field(default_factory=list)
    deletions: list = field(default_factory=list)
    objects_seen: dict = field(default_factory=dict)
    skipped: Counter = field(default_factory=Counter)
    errors: list = field(default_factory=list)
    duplicates_dropped: int = 0


def _j(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _unquote(value):
    """modifiedProperties values are often JSON-encoded strings like "\"abc\""."""
    if value is None:
        return None
    v = _j(value)
    if isinstance(v, str):
        return v.strip().strip('"')
    return v


def _prop(target: dict, name: str, which: str):
    for p in target.get("modifiedProperties") or []:
        if (p.get("displayName") or "").lower() == name.lower():
            return _unquote(p.get(which))
    return None


def _norm_op(op: str) -> str:
    return " ".join(op.replace("\u2013", "-").replace("\u2014", "-").lower().split())


def _initiator(row) -> str | None:
    ib = _j(row.get("InitiatedBy")) or {}
    user = ib.get("user") or {}
    app = ib.get("app") or {}
    ident = user.get("id") or app.get("servicePrincipalId")
    return ident.lower() if ident else None


def _remember(parsed: ParsedLog, obj_id, obj_type, name):
    if obj_id and obj_id.lower() not in parsed.objects_seen:
        parsed.objects_seen[obj_id.lower()] = {"type": obj_type, "displayName": name}


def _first(targets, types):
    for t in targets:
        if t.get("type") in types and t.get("id"):
            return t
    return None


def _key_ids(raw) -> set:
    if raw is None:
        return set()
    text = raw if isinstance(raw, str) else json.dumps(raw)
    return {k.lower() for k in _KEYID.findall(text)}


def load_rows(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def parse_rows(rows: list) -> ParsedLog:
    parsed = ParsedLog()
    for seq, row in enumerate(rows):
        op_raw = row.get("OperationName") or ""
        op = _norm_op(op_raw)
        if (row.get("Result") or "").lower() != "success":
            parsed.skipped[f"non-success: {op_raw}"] += 1
            continue
        try:
            handled = _dispatch(parsed, row, op, op_raw, seq)
        except Exception as exc:  # keep going, report later
            parsed.errors.append(f"{row.get('Id')}: {op_raw}: {exc}")
            continue
        if not handled:
            parsed.skipped[op_raw] += 1
    _dedupe(parsed)
    return parsed


DUP_WINDOW_SECONDS = 60


def _dedupe(parsed: ParsedLog) -> None:
    """Entra writes some changes 2-4 times. Collapse repeats of the same action on the same edge
    (or deletion of the same object) within DUP_WINDOW_SECONDS, with no opposite action between.
    Without this, each extra copy looks like an add with no matching removal, and the engine
    invents an interval that can run until a later object deletion."""
    last, keep = {}, []
    for d in sorted(parsed.deltas, key=lambda x: (x.time, x.seq)):
        prev = last.get(d.edge)
        if prev and prev[0] == d.action and (d.time - prev[1]).total_seconds() <= DUP_WINDOW_SECONDS:
            parsed.duplicates_dropped += 1
            continue
        last[d.edge] = (d.action, d.time)
        keep.append(d)
    parsed.deltas = keep
    seen, keep = {}, []
    for x in sorted(parsed.deletions, key=lambda x: (x.time, x.seq)):
        prev = seen.get(x.object_id)
        if prev and (x.time - prev).total_seconds() <= DUP_WINDOW_SECONDS:
            parsed.duplicates_dropped += 1
            continue
        seen[x.object_id] = x.time
        keep.append(x)
    parsed.deletions = keep


def _dispatch(parsed: ParsedLog, row, op, op_raw, seq) -> bool:
    t = parse_time(row["TimeGenerated"])
    eid = row.get("Id") or f"row{seq}"
    targets = _j(row.get("TargetResources")) or []
    init = _initiator(row)

    def emit(action, edge, **kw):
        parsed.deltas.append(Delta(t, action, edge, op_raw, eid, seq, init, **kw))

    # Group membership
    if op in ("add member to group", "remove member from group"):
        add = op.startswith("add")
        member = targets[0]
        gid = _prop(member, "Group.ObjectID", "newValue" if add else "oldValue")
        if not gid and len(targets) > 1:
            gid = targets[1].get("id")
        _remember(parsed, member["id"], member.get("type"), member.get("displayName") or member.get("userPrincipalName"))
        _remember(parsed, gid, "Group", _prop(member, "Group.DisplayName", "newValue" if add else "oldValue"))
        emit("add" if add else "remove", EdgeKey(MEMBER_OF, member["id"].lower(), gid.lower()))
        return True

    # Directory roles, including PIM activation and expiry
    pim_add = op.startswith("add member to role completed (pim activation")
    pim_remove = op.startswith("remove member from role (pim activation expired")
    if op in ("add member to role", "remove member from role") or pim_add or pim_remove:
        add = op.startswith("add")
        principal = _first(targets, PRINCIPAL_TYPES)
        tmpl = None
        if principal is not None:
            tmpl = _prop(principal, "Role.TemplateId", "newValue" if add else "oldValue")
        if not tmpl:
            role_t = _first(targets, {"Role"})
            tmpl = role_t.get("id") if role_t else None
        if principal is None or not tmpl:
            raise ValueError("could not resolve principal or role")
        role_name = _prop(principal, "Role.DisplayName", "newValue" if add else "oldValue")
        if not role_name:
            rt = _first(targets, {"Role"})
            role_name = rt.get("displayName") if rt else None
        _remember(parsed, principal["id"], principal.get("type"), principal.get("displayName") or principal.get("userPrincipalName"))
        _remember(parsed, role_node(tmpl), "DirectoryRole", role_name)
        expires, ptid = None, None
        for d in _j(row.get("AdditionalDetails")) or []:
            k = (d.get("key") or "").lower()
            if pim_add and k in EXPIRY_KEYS and d.get("value"):
                expires = parse_time(d["value"])
            if k == "principal tenant id" and d.get("value"):
                ptid = d["value"].lower()
        if ptid:
            parsed.objects_seen[principal["id"].lower()]["principalTenantId"] = ptid
        emit("add" if add else "remove", EdgeKey(HAS_ROLE, principal["id"].lower(), role_node(tmpl)),
             pim=pim_add or pim_remove, pim_expires=expires)
        return True

    # Ownership of applications and service principals
    for kind, prop in (("application", "Application.ObjectID"), ("service principal", "ServicePrincipal.ObjectID")):
        if op in (f"add owner to {kind}", f"remove owner from {kind}"):
            add = op.startswith("add")
            owner = targets[0]
            obj = _prop(owner, prop, "newValue" if add else "oldValue")
            if not obj and len(targets) > 1:
                obj = targets[1].get("id")
            _remember(parsed, owner["id"], owner.get("type"), owner.get("displayName") or owner.get("userPrincipalName"))
            emit("add" if add else "remove", EdgeKey(OWNS, owner["id"].lower(), obj.lower()))
            return True

    # Credentials: diff KeyDescription old vs new
    if "certificates and secrets management" in op or op in (
            "add service principal credentials", "remove service principal credentials",
            "update service principal credentials"):
        tgt = targets[0]
        _remember(parsed, tgt["id"], tgt.get("type"), tgt.get("displayName"))
        old_ids = _key_ids(_prop(tgt, "KeyDescription", "oldValue"))
        new_ids = _key_ids(_prop(tgt, "KeyDescription", "newValue"))
        for k in sorted(new_ids - old_ids):
            emit("add", EdgeKey(CREDENTIAL, key_node(k), tgt["id"].lower()), holder=init)
        for k in sorted(old_ids - new_ids):
            emit("remove", EdgeKey(CREDENTIAL, key_node(k), tgt["id"].lower()))
        return True

    # Object deletions (used to infer when unlogged edge removals happened)
    if op in ("delete user", "hard delete user", "delete group", "hard delete group", "delete application",
              "hard delete application", "delete service principal", "remove service principal",
              "hard delete service principal"):
        tgt = targets[0]
        _remember(parsed, tgt["id"], tgt.get("type"), tgt.get("displayName") or tgt.get("userPrincipalName"))
        parsed.deletions.append(ObjectDeletion(t, tgt["id"].lower(), op_raw, eid, seq))
        return True

    # Ignored pending evidence: may duplicate Core Directory events. See PIM PAIRING in itm.shapes.
    if op.startswith("add member to role outside of pim") or op.startswith("remove member from role outside of pim"):
        parsed.skipped[f"ignored duplicate: {op_raw}"] += 1
        return True

    return False
