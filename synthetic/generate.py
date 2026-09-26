"""Synthetic tenant simulator for Identity Time Machine.

Simulates ~12 weeks of Entra changes, keeps the TRUE graph state independently of
the engine, and writes:
  data/auditlogs.json  AuditLogs rows in Log Analytics export shape (dynamic cols as JSON strings)
  data/anchor.json     graph state at the anchor time (what a Graph API snapshot would return)
  data/truth.json      true edge sets at checkpoints + true ephemeral tier-0 reach

Deliberate logging imperfections (the engine must cope):
  * pre-window edges never appear in logs
  * a PIM activation whose expiry is not logged but whose ExpirationTime is
  * a PIM activation with neither expiry event nor ExpirationTime
  * user deletions with no per-membership removal events
  * a failed attempt that must not create an edge
  * irrelevant operations mixed in
"""
from __future__ import annotations

import json
import random
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

NS = uuid.UUID("7d1a2c4e-0000-4000-8000-17e0715e0001")
UTC = timezone.utc
T0 = datetime(2026, 7, 1, 0, 0, tzinfo=UTC)
ANCHOR = datetime(2026, 9, 26, 8, 0, tzinfo=UTC)
DOMAIN = "contoso.com"
PEOPLE = {  # internal key -> (display name, UPN prefix)
    "alice": ("Alice Moreno", "alice.moreno"), "bob": ("Bob Keller", "bob.keller"),
    "carol": ("Carol Diaz", "carol.diaz"), "dave": ("Dave Miller", "dave.miller"),
    "erin": ("Erin Walsh", "erin.walsh"), "frank": ("Frank Osei", "frank.osei"),
    "grace": ("Grace Lin", "grace.lin"), "heidi": ("Heidi Novak", "heidi.novak"),
    "ivan": ("Ivan Petrov", "ivan.petrov"), "judy": ("Judy Chen", "judy.chen"),
    "temp-contractor": ("Contractor (temp)", "ext.contractor"),
}
HOME_TENANT = str(uuid.uuid5(uuid.UUID("7d1a2c4e-0000-4000-8000-17e0715e0001"), "tenant"))
PARTNER_TENANT = str(uuid.uuid5(uuid.UUID("7d1a2c4e-0000-4000-8000-17e0715e0001"), "tenant:partner"))

ROLES = {
    "Global Administrator": "62e90394-69f5-4237-9190-012177145e10",
    "Privileged Role Administrator": "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "Application Administrator": "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
    "Cloud Application Administrator": "158c047a-c907-4556-b7ef-446551a6b5f7",
    "Helpdesk Administrator": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
}
TIER0 = {ROLES[n] for n in ("Global Administrator", "Privileged Role Administrator",
                           "Application Administrator", "Cloud Application Administrator")}


def gid(name: str) -> str:
    return str(uuid.uuid5(NS, name))


def iso7(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}0Z"


def at(month, day, hh=0, mm=0):
    return datetime(2026, month, day, hh, mm, tzinfo=UTC)


class Sim:
    def __init__(self):
        self.objects = {}
        self.rows = []
        self.open = {}          # edge tuple -> (start, holder)
        self.closed = []        # (edge, start, end, holder)
        self.app_keys = defaultdict(list)  # app/sp id -> [(keyId, name)]
        self.rng = random.Random(42)

    # objects
    def user(self, n):
        i = gid("user:" + n)
        display, upn = PEOPLE.get(n, (n, n))
        self.objects[i] = {"type": "User", "displayName": display, "userPrincipalName": f"{upn}@{DOMAIN}"}
        return i

    def group(self, n):
        i = gid("group:" + n)
        self.objects[i] = {"type": "Group", "displayName": n}
        return i

    def app(self, n):
        a, s = gid("app:" + n), gid("sp:" + n)
        self.objects[a] = {"type": "Application", "displayName": n, "appId": gid("appid:" + n)}
        self.objects[s] = {"type": "ServicePrincipal", "displayName": n + " (SP)", "appId": gid("appid:" + n)}
        self._open(("backs", a, s), None)
        return a, s

    def role(self, n):
        i = "role:" + ROLES[n]
        self.objects[i] = {"type": "DirectoryRole", "displayName": n}
        return ROLES[n]

    # truth
    def _open(self, e, t, holder=None):
        assert e not in self.open, f"already open {e}"
        self.open[e] = (t, holder)

    def _close(self, e, t):
        s, h = self.open.pop(e)
        self.closed.append((e, s, t, h))

    def has(self, e):
        return e in self.open

    # rows
    def _tgt(self, i, mods=()):
        o = self.objects[i]
        return {"id": i, "displayName": o.get("displayName") if o["type"] != "User" else None,
                "userPrincipalName": o.get("userPrincipalName"), "type": o["type"],
                "modifiedProperties": list(mods)}

    @staticmethod
    def _mp(name, old=None, new=None):
        return {"displayName": name,
                "oldValue": json.dumps(old) if old is not None else None,
                "newValue": json.dumps(new) if new is not None else None}

    def _row(self, t, op, targets, init, category, service="Core Directory", result="success", details=()):
        ib = {"user": {"id": init, "userPrincipalName": self.objects[init].get("userPrincipalName"),
                       "ipAddress": "203.0.113.%d" % self.rng.randint(2, 250)}}
        self.rows.append({
            "TimeGenerated": iso7(t), "Id": "Directory_" + uuid.UUID(int=self.rng.getrandbits(128)).hex[:20].upper(),
            "OperationName": op, "Category": category, "Result": result, "LoggedByService": service,
            "CorrelationId": str(uuid.UUID(int=self.rng.getrandbits(128))), "InitiatedBy": json.dumps(ib),
            "TargetResources": json.dumps(targets), "AdditionalDetails": json.dumps(list(details)),
        })

    # operations
    def add_member(self, t, m, g, init, result="success"):
        mods = [self._mp("Group.ObjectID", new=g), self._mp("Group.DisplayName", new=self.objects[g]["displayName"])]
        self._row(t, "Add member to group", [self._tgt(m, mods), self._tgt(g)], init, "GroupManagement", result=result)
        if result == "success":
            self._open(("member_of", m, g), t)

    def remove_member(self, t, m, g, init):
        mods = [self._mp("Group.ObjectID", old=g), self._mp("Group.DisplayName", old=self.objects[g]["displayName"])]
        self._row(t, "Remove member from group", [self._tgt(m, mods), self._tgt(g)], init, "GroupManagement")
        self._close(("member_of", m, g), t)

    def foreign_group(self, n, tenant):
        i = gid("foreign:" + n)
        self.objects[i] = {"type": "Group", "displayName": n, "foreign": True, "tenant": tenant}
        return i

    def _role_row(self, t, op, p, tmpl, init):
        name = self.objects["role:" + tmpl]["displayName"]
        add = op.startswith("Add")
        mods = [self._mp("Role.ObjectID", **({"new": gid("roleobj:" + tmpl)} if add else {"old": gid("roleobj:" + tmpl)})),
                self._mp("Role.DisplayName", **({"new": name} if add else {"old": name})),
                self._mp("Role.TemplateId", **({"new": tmpl} if add else {"old": tmpl}))]
        role_t = {"id": gid("roleobj:" + tmpl), "displayName": name, "type": "Role", "modifiedProperties": []}
        ptid = self.objects[p].get("tenant") or HOME_TENANT
        self._row(t, op, [self._tgt(p, mods), role_t], init, "RoleManagement",
                  details=[{"key": "Principal Tenant ID", "value": ptid}])

    def add_role(self, t, p, tmpl, init):
        self._role_row(t, "Add member to role", p, tmpl, init)
        self._open(("has_role", p, "role:" + tmpl), t)

    def remove_role(self, t, p, tmpl, init):
        self._role_row(t, "Remove member from role", p, tmpl, init)
        self._close(("has_role", p, "role:" + tmpl), t)

    def pim_activate(self, t, p, tmpl, hours, init, log_expiry_detail=True):
        name = self.objects["role:" + tmpl]["displayName"]
        role_t = {"id": tmpl, "displayName": name, "type": "Role", "modifiedProperties": []}
        details = [{"key": "ExpirationTime", "value": iso7(t + timedelta(hours=hours))}] if log_expiry_detail else []
        self._row(t, "Add member to role completed (PIM activation)", [role_t, self._tgt(p)], init,
                  "RoleManagement", service="PIM", details=details)
        self._open(("has_role", p, "role:" + tmpl), t)

    def pim_expire(self, t, p, tmpl, log=True):
        if log:
            name = self.objects["role:" + tmpl]["displayName"]
            role_t = {"id": tmpl, "displayName": name, "type": "Role", "modifiedProperties": []}
            self._row(t, "Remove member from role (PIM activation expired)", [role_t, self._tgt(p)], p,
                      "RoleManagement", service="PIM")
        self._close(("has_role", p, "role:" + tmpl), t)

    def add_owner(self, t, owner, target, init):
        kind, prop = (("application", "Application.ObjectID") if self.objects[target]["type"] == "Application"
                      else ("service principal", "ServicePrincipal.ObjectID"))
        self._row(t, f"Add owner to {kind}", [self._tgt(owner, [self._mp(prop, new=target)]), self._tgt(target)],
                  init, "ApplicationManagement")
        self._open(("owns", owner, target), t)

    def remove_owner(self, t, owner, target, init):
        kind, prop = (("application", "Application.ObjectID") if self.objects[target]["type"] == "Application"
                      else ("service principal", "ServicePrincipal.ObjectID"))
        self._row(t, f"Remove owner from {kind}", [self._tgt(owner, [self._mp(prop, old=target)]), self._tgt(target)],
                  init, "ApplicationManagement")
        self._close(("owns", owner, target), t)

    def _keydesc(self, keys):
        return [f"[KeyIdentifier={k},KeyType=Password,KeyUsage=Verify,DisplayName={n}]" for k, n in keys]

    def seed_key(self, target, key, name):
        self.app_keys[target].append((key, name))
        self._open(("credential", "key:" + key, target), None, None)

    def add_key(self, t, target, key, name, init):
        old = list(self.app_keys[target])
        self.app_keys[target].append((key, name))
        self._key_row(t, target, old, self.app_keys[target], init, add=True)
        self._open(("credential", "key:" + key, target), t, init)

    def remove_key(self, t, target, key, init):
        old = list(self.app_keys[target])
        self.app_keys[target] = [kv for kv in old if kv[0] != key]
        self._key_row(t, target, old, self.app_keys[target], init, add=False)
        self._close(("credential", "key:" + key, target), t)

    def _key_row(self, t, target, old, new, init, add):
        if self.objects[target]["type"] == "Application":
            op = "Update application \u2013 Certificates and secrets management "
            mods = [self._mp("KeyDescription", old=self._keydesc(old), new=self._keydesc(new))]
        else:
            op = "Add service principal credentials" if add else "Remove service principal credentials"
            diff = [kv for kv in (new if add else old) if kv not in (old if add else new)]
            mods = [self._mp("KeyDescription", old=None if add else self._keydesc(diff),
                             new=self._keydesc(diff) if add else None)]
        self._row(t, op, [self._tgt(target, mods)], init, "ApplicationManagement")

    def delete_user(self, t, u, init):
        self._row(t, "Delete user", [self._tgt(u)], init, "UserManagement")
        for e in [e for e in self.open if u in (e[1], e[2])]:
            self._close(e, t)  # cascade happens silently, as in real Entra

    def noise_op(self, t, u, init):
        op = self.rng.choice(["Update user", "Reset user password", "Update group", "Add registered owner to device"])
        self._row(t, op, [self._tgt(u)], init, "UserManagement")

    # truth queries
    def intervals(self):
        out = list(self.closed)
        out += [(e, s, None, h) for e, (s, h) in self.open.items()]
        return out


def truth_state(ivs, t):
    return {e: h for e, s, end, h in ivs if (s is None or s <= t) and (end is None or t < end)}


def truth_tier0(state, objects):
    adj = defaultdict(set)
    for e, h in state.items():
        src = h if e[0] == "credential" else e[1]
        if src:
            adj[src].add(e[2])
    pairs = set()
    for actor, o in objects.items():
        if o["type"] not in ("User", "ServicePrincipal") and not o.get("foreign"):
            continue
        seen, q = {actor}, deque([actor])
        while q:
            n = q.popleft()
            for d in adj[n]:
                if d not in seen:
                    seen.add(d)
                    q.append(d)
        pairs |= {(actor, n) for n in seen if n.startswith("role:") and n[5:] in TIER0}
    return pairs


def build():
    s = Sim()
    # identities
    alice, bob, carol, dave, erin, frank, grace, heidi, ivan, judy = (
        s.user(n) for n in ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"])
    contractor = s.user("temp-contractor")
    noise_users = [s.user(f"user{i:02d}") for i in range(1, 13)]
    staff = [alice, bob, carol, dave, erin, frank, grace, heidi, ivan, judy] + noise_users
    it_admins, tier0_ops, phoenix = s.group("IT-Admins"), s.group("Tier0-Ops"), s.group("Project-Phoenix")
    noise_groups = [s.group(n) for n in ["All-Staff", "Developers", "Helpdesk", "Sales", "Finance"]]
    helpdesk = noise_groups[2]
    backup_app, backup_sp = s.app("Backup-Automation")
    hr_app, hr_sp = s.app("HR-Portal")
    rep_app, rep_sp = s.app("Reporting-Tool")
    GA, PRA, APPA, CAA, HDA = (s.role(n) for n in ROLES)
    partner_admins = s.foreign_group("partner-admins", PARTNER_TENANT)     # tier-0 grants predating the log window
    partner_temp = s.foreign_group("partner-escalation", PARTNER_TENANT)

    # pre-window state (never logged)
    for e in [("has_role", it_admins, "role:" + GA), ("member_of", tier0_ops, it_admins),
              ("member_of", bob, it_admins), ("has_role", helpdesk, "role:" + HDA),
              ("member_of", alice, helpdesk), ("has_role", backup_sp, "role:" + PRA),
              ("has_role", rep_sp, "role:" + CAA), ("owns", erin, hr_app),
              ("has_role", partner_admins, "role:" + PRA)]:
        s._open(e, None)
    for u in staff:
        s._open(("member_of", u, noise_groups[0]), None)
    for u in noise_users[:6]:
        s._open(("member_of", u, noise_groups[1]), None)
    s.seed_key(backup_app, gid("key:K1"), "backup-prod")
    s.seed_key(hr_app, gid("key:K2"), "hr-2025")

    actions = []  # (time, fn)

    def A(t, fn):
        actions.append((t, fn))

    # scenario: deleted contractor (no membership removal logged)
    A(at(7, 8, 10), lambda: s.add_member(at(7, 8, 10), contractor, it_admins, bob))
    A(at(7, 22, 17), lambda: s.delete_user(at(7, 22, 17), contractor, bob))
    # scenario: temporal trap. frank never co-exists with the nesting
    A(at(7, 10, 9), lambda: s.add_member(at(7, 10, 9), frank, phoenix, bob))
    A(at(7, 12, 18), lambda: s.remove_member(at(7, 12, 18), frank, phoenix, bob))
    A(at(7, 20, 11), lambda: s.add_member(at(7, 20, 11), phoenix, it_admins, bob))
    A(at(8, 5, 15), lambda: s.remove_member(at(8, 5, 15), phoenix, it_admins, bob))
    # scenario: persistent ownership (tier-0 at anchor, so NOT ephemeral)
    A(at(7, 15, 12), lambda: s.add_owner(at(7, 15, 12), grace, rep_app, bob))
    # scenario: PIM, three logging qualities
    A(at(8, 3, 9), lambda: s.pim_activate(at(8, 3, 9), carol, GA, 4, carol))
    A(at(8, 3, 13), lambda: s.pim_expire(at(8, 3, 13), carol, GA, log=True))
    A(at(8, 17, 9), lambda: s.pim_activate(at(8, 17, 9), carol, GA, 4, carol))
    A(at(8, 17, 13), lambda: s.pim_expire(at(8, 17, 13), carol, GA, log=False))
    A(at(8, 20, 10), lambda: s.pim_activate(at(8, 20, 10), heidi, APPA, 2, heidi, log_expiry_detail=False))
    A(at(8, 20, 12), lambda: s.pim_expire(at(8, 20, 12), heidi, APPA, log=False))
    # a local, non-tier-0 role grant (carries the home Principal Tenant ID, as real events do)
    A(at(7, 18, 9), lambda: s.add_role(at(7, 18, 9), judy, HDA, bob))
    # scenario: a foreign group gets a tier-0 role for 6 hours, removed before the anchor
    A(at(8, 12, 10), lambda: s.add_role(at(8, 12, 10), partner_temp, APPA, bob))
    A(at(8, 12, 16), lambda: s.remove_role(at(8, 12, 16), partner_temp, APPA, bob))
    # scenario: temporary app ownership -> SP role
    A(at(8, 25, 10), lambda: s.add_owner(at(8, 25, 10), ivan, rep_app, bob))
    A(at(8, 28, 16), lambda: s.remove_owner(at(8, 28, 16), ivan, rep_app, bob))
    # benign credential rotation on a non-privileged app, plus an SP credential
    A(at(8, 10, 14), lambda: s.add_key(at(8, 10, 14), hr_app, gid("key:K3"), "hr-2026", erin))
    A(at(8, 10, 14, 5), lambda: s.remove_key(at(8, 10, 14, 5), hr_app, gid("key:K2"), erin))
    A(at(9, 10, 9), lambda: s.add_key(at(9, 10, 9), hr_sp, gid("key:K5"), "hr-sp-cert", erin))
    # scenario: the attack. failed try, add-act-remove, credential backdoor, cleanup
    A(at(9, 2, 2, 10), lambda: s.add_member(at(9, 2, 2, 10), dave, it_admins, dave, result="failure"))
    A(at(9, 2, 2, 14), lambda: s.add_member(at(9, 2, 2, 14), dave, tier0_ops, dave))
    A(at(9, 2, 2, 40), lambda: s.add_key(at(9, 2, 2, 40), backup_app, gid("key:K4"), "sync-temp", dave))
    A(at(9, 2, 4, 31), lambda: s.remove_member(at(9, 2, 4, 31), dave, tier0_ops, dave))
    A(at(9, 5, 11), lambda: s.remove_key(at(9, 5, 11), backup_app, gid("key:K4"), dave))
    # a noise user deleted late (its pre-window memberships are unrecoverable by design)
    A(at(9, 15, 16), lambda: s.delete_user(at(9, 15, 16), noise_users[-1], bob))

    # background noise
    rng = random.Random(7)
    span = int((ANCHOR - T0).total_seconds())
    deleted = {noise_users[-1]: at(9, 15, 16)}
    for _ in range(220):
        t = T0 + timedelta(seconds=rng.randint(0, span - 3600))
        t = t.replace(microsecond=rng.randint(0, 999999))
        u, g = rng.choice(noise_users), rng.choice(noise_groups[1:])
        if u in deleted and t >= deleted[u]:
            continue

        def flip(t=t, u=u, g=g):
            if u in deleted and t >= deleted[u]:
                return
            if s.has(("member_of", u, g)):
                s.remove_member(t, u, g, bob)
            else:
                s.add_member(t, u, g, bob)
        A(t, flip)
    for _ in range(120):
        t = T0 + timedelta(seconds=rng.randint(0, span - 3600), microseconds=rng.randint(0, 999999))
        u = rng.choice(staff[:10])
        A(t, lambda t=t, u=u: s.noise_op(t, u, bob))

    for t, fn in sorted(actions, key=lambda x: x[0]):
        fn()

    ivs = s.intervals()
    return s, ivs


def main():
    out = Path(__file__).resolve().parent.parent / "data"
    out.mkdir(exist_ok=True)
    s, ivs = build()

    # anchor: graph state now, only objects that still exist
    now = truth_state(ivs, ANCHOR)
    deleted_ids = {json.loads(r["TargetResources"])[0]["id"] for r in s.rows if r["OperationName"] == "Delete user"}
    anchor_objects = {k: v for k, v in s.objects.items() if k not in deleted_ids and not v.get("foreign")}
    for e in now:
        if e[0] == "has_role" and s.objects.get(e[1], {}).get("foreign"):
            anchor_objects[e[1]] = {"type": "ForeignPrincipal", "displayName": None}
    anchor = {"captured_at": iso7(ANCHOR), "tenant_id": HOME_TENANT, "objects": anchor_objects,
              "edges": [{"type": e[0], "src": e[1], "dst": e[2]} for e in sorted(now)]}

    # checkpoints: every 6 hours plus moments inside each scenario
    cps = []
    t = T0 + timedelta(hours=1)
    while t < ANCHOR:
        cps.append(t)
        t += timedelta(hours=6)
    cps += [at(9, 2, 3, 0), at(9, 2, 3, 30), at(9, 3, 0), at(8, 17, 11), at(8, 20, 11), at(8, 20, 15),
            at(7, 21, 0), at(7, 11, 0), at(8, 26, 0)]
    checkpoints = [{"time": iso7(c), "edges": [list(e) for e in sorted(truth_state(ivs, c))]} for c in sorted(cps)]

    # true ephemeral tier-0 reach over the full window
    pts = sorted({T0} | {p for _, a, b, _ in ivs for p in (a, b) if p is not None and T0 < p < ANCHOR})
    anchor_pairs = truth_tier0(now, s.objects)
    open_, spans = {}, defaultdict(list)
    for p in pts:
        cur = truth_tier0(truth_state(ivs, p), s.objects) - anchor_pairs
        for k in cur - set(open_):
            open_[k] = p
        for k in set(open_) - cur:
            spans[k].append([iso7(open_.pop(k)), iso7(p)])
    for k, st in open_.items():
        spans[k].append([iso7(st), iso7(ANCHOR)])
    ephemeral = [{"actor": a, "actor_name": s.objects[a]["displayName"], "role": r,
                  "role_name": s.objects[r]["displayName"], "spans": v} for (a, r), v in sorted(spans.items())]

    truth = {"window_start": iso7(T0), "anchor": iso7(ANCHOR), "checkpoints": checkpoints,
             "ephemeral_tier0": ephemeral, "objects": s.objects,
             "trap": {"principal": gid("user:frank"), "role": "role:" + ROLES["Global Administrator"],
                      "note": "frank left Project-Phoenix before it was nested into IT-Admins"}}

    # Entra writes some changes more than once (seen 2x-4x in a real tenant). Replicate that.
    rng = random.Random(99)
    dup = []
    for r in s.rows:
        op = r["OperationName"]
        tr = r["TargetResources"]
        n = 0
        if "Certificates and secrets" in op and gid("key:K4") in tr:
            n = 2                      # dave's backdoor key: add and removal logged 3x
        elif op == "Delete user":
            n = 3                      # deletions logged 4x
        elif gid("user:user12") in tr and op in ("Add member to group", "Remove member from group"):
            n = 1                      # the real-tenant failure mode: dup add + later removal + later deletion
        elif op in ("Add member to group", "Remove member from group") and rng.random() < 0.08:
            n = 1
        for _ in range(n):
            d = dict(r)
            d["Id"] = "Directory_" + uuid.UUID(int=rng.getrandbits(128)).hex[:20].upper()
            dup.append(d)
    rows = sorted(s.rows + dup, key=lambda r: r["TimeGenerated"])
    (out / "auditlogs.json").write_text(json.dumps(rows, indent=1))
    (out / "anchor.json").write_text(json.dumps(anchor, indent=1))
    (out / "truth.json").write_text(json.dumps(truth, indent=1))
    print(f"rows={len(rows)} anchor_edges={len(anchor['edges'])} checkpoints={len(checkpoints)} "
          f"true_ephemeral_pairs={len(ephemeral)}")


if __name__ == "__main__":
    main()
