# Identity Time Machine

[![tests](https://github.com/KanenasCS/identity-time-machine/actions/workflows/tests.yml/badge.svg)](https://github.com/KanenasCS/identity-time-machine/actions/workflows/tests.yml)

Reconstructs the Microsoft Entra ID identity graph at any past moment inside your audit log window, and finds **ephemeral privileged paths**: tier-0 access that existed for some time but no longer exists. The classic case is an attacker who adds themselves to a privileged group, acts, and removes themselves. Current-state tools see nothing.

Pure Python 3.9+, no dependencies (optional `azure-identity` for app-based auth). Read-only against your tenant.

```bash
pip install .            # installs the itm, itm-collect and itm-shapes commands
pip install .[sdk]       # adds azure-identity for --auth sdk
```

Every `python -m itm ...` example below also works as `itm ...` once installed.

## Status

| Area | Validation |
|---|---|
| Engine | Synthetic ground truth, 359 checkpoints: edge precision 0.9999, recall 0.9861, 7 of 7 ephemeral tier-0 paths, temporal trap correct |
| Collector | Round-trip against a fake Graph with paging, throttling, token expiry, noise objects |
| Real tenant | 90-day window: 0 parse errors, duplicate rows collapsed, 0 conflicts, principals outside the directory detected |
| Rebuild of a real past state | Pending: run the acceptance test below |

## What it answers

* What could this account reach at 03:14 last Tuesday?
* What could it reach at any point during the incident window?
* Which tier-0 paths existed in the last 90 days but not now?
* Which roles are held by principals outside this directory, and since when?

## Quickstart (offline)

```bash
python synthetic/run_all.py        # generate a synthetic tenant and run every test
A="--anchor data/anchor.json --logs data/auditlogs.json"
python -m itm $A ephemeral --from 2026-07-02T00:00:00Z
python -m itm $A reach dave --at 2026-09-02T03:00:00Z
python -m itm $A window-reach frank --from 2026-07-02T00:00:00Z --naive
```

## Real tenant

Anchor and log files contain identity data. `.gitignore` blocks them. Keep them internal.

```bash
az login --tenant <tenant-id>
WS=<workspace-customer-id>; TENANT=<tenant-id>

# 1. snapshot first, so the log export covers everything up to it
python -m itm.collect --out anchor.json --tenant $TENANT

# 2. wait ~30 min for AuditLogs ingestion, then export
az monitor log-analytics query -w $WS --timespan P90D \
  --analytics-query "$(cat queries/auditlogs_export.kql)" -o json > auditlogs.json

# 3. validate and hunt
python -m itm.shapes auditlogs.json > shapes.txt     # redacted parser-assumption report
A="--anchor anchor.json --logs auditlogs.json"
python -m itm $A summary                              # conflicts = accuracy signal
python -m itm $A ephemeral --from <start>
python -m itm $A foreign
```

Use Cloud Shell Bash. In PowerShell, `$(cat file.kql)` joins lines and the first `//` comment breaks the query.

**Auth.** Default uses the az CLI token (needs at least Global Reader). If an endpoint returns 403, use an app registration with `User.Read.All`, `GroupMember.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory` and `--auth sdk`.

## Acceptance test (prove it on your tenant)

1. `python -m itm.collect --out anchor_A.json --tenant $TENANT`
2. Make harmless, timed test changes: a role-assignable test group with Message Center Reader, a test user added then removed, a test app with a secret added then deleted, the test user re-added then deleted.
3. Wait 30 min. `python -m itm.collect --out anchor_B.json --tenant $TENANT`, then export `auditlogs.json`.
4. Run:

```bash
python -m itm --anchor anchor_B.json --logs auditlogs.json replay-check --baseline anchor_A.json
python -m itm --anchor anchor_B.json --logs auditlogs.json history itm-test-group
python -m itm --anchor anchor_B.json --logs auditlogs.json history itm-test-app
```

**Pass:** `replay-check` prints `RESULT: PASS` (0 missing, 0 extra), and the history intervals match your noted times. Delete the test objects afterwards.

## Commands

| Command | Purpose |
|---|---|
| `summary` | Window, parse stats, duplicates dropped, foreign principals, conflicts |
| `state-at T` | Every edge present at T |
| `reach P --at T` | Roles a principal could reach at T, with paths |
| `window-reach P --from --to [--naive]` | Everything reachable at any moment in a window |
| `ephemeral --from --to [--hide-pim]` | Tier-0 reach that existed in the window but not now |
| `foreign` | Roles held by principals outside the directory, over time |
| `history OBJ` | Every interval touching an object |
| `replay-check --baseline A` | Acceptance test: rebuild an earlier snapshot |
| `python -m itm.collect` | Read-only Graph snapshot (anchor) |
| `python -m itm.shapes LOGS` | Redacted structure report for parser validation |

## How it works

**Anchor plus reverse replay.** The anchor is the graph now. The engine walks audit events newest to oldest and inverts each: an add closes an interval, a remove opens one. Output is edge validity intervals with confidence and notes.

**Unlogged removals** are inferred in order: deletion of an endpoint, PIM expiry time, next add of the same edge, default PIM duration, otherwise present until the anchor (conservative).

**Duplicate rows.** Entra can write one change several times. Repeats of the same action on the same edge within 60 seconds are collapsed.

**Temporally correct windows.** Reach over a window is evaluated at every change point, never on the union of all edges seen, which would invent paths whose edges never co-existed.

**Foreign principals.** A principal is typed `ForeignPrincipal` when the collector cannot find it in the directory, when its `Principal Tenant ID` differs from the home tenant, or when it holds a role and never appears in the directory. Foreign principals count as actors in every report.

**Edges:** `member_of`, `has_role`, `owns`, `credential` (attributed to whoever added it), `backs` (app to its service principal).

## Limitations

* Lookback equals AuditLogs retention.
* Edges granted before the window and removed silently inside it cannot be recovered from logs.
* Credentials that predate the window have an unknown holder.
* Not modeled yet: app role assignments, federated identity credentials, group owners, delegated permission grants, PIM eligibility, Azure RBAC.
* Snapshots are not atomic. Changes during collection can appear as conflicts.

## Roadmap

App role edges with tier-0 Graph permissions; federated credentials and app role snapshots in the collector; group owners; daily anchors with forward replay; accuracy check against Entra Backup and Recovery; MCP interface.

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
