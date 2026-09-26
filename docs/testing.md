# Testing

## Offline suite

```bash
python synthetic/run_all.py
```

The suite builds a synthetic tenant with a known true history and checks the tool against it.

| Test | What it proves |
|---|---|
| `evaluate.py` | Reconstructed edges match the true graph at 359 checkpoints, all ephemeral tier-0 paths are found with exact times, and the temporal trap is handled |
| `test_collector.py` | The collector reproduces the true snapshot from a simulated Graph API with small pages, throttling, an expired token and noise objects |
| `test_foreign.py` | Foreign principals are detected with both current and older snapshot formats |
| `test_replay.py` | `replay-check` passes on a true earlier state and fails on a tampered one |

The synthetic history includes the conditions that break naive implementations: nested group escalation with cleanup, a credential backdoor on a privileged app, temporary ownership, silent deletion cascades, PIM activations with incomplete logging, a failed attempt, duplicate audit rows, foreign role grants, and a temporal trap where two edges never co-exist.

## Verifying on your own tenant

`replay-check` proves the tool can rebuild a real past state exactly.

1. Take snapshot A: `itm-collect --out anchor_A.json --tenant <id>`
2. Make harmless, timed changes. For example: create a role-assignable test group holding Message Center Reader, add and remove a test user, add and delete a secret on a test app, re-add the test user and then delete them.
3. Wait about 30 minutes. Take snapshot B and export the audit logs.
4. Run:

```bash
itm --anchor anchor_B.json --logs auditlogs.json replay-check --baseline anchor_A.json
itm --anchor anchor_B.json --logs auditlogs.json history <test-group>
```

`replay-check` must print `RESULT: PASS` (no missing and no extra edges), and the history intervals must match the times you noted. Remove the test objects afterwards.
