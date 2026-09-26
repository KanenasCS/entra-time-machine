"""replay-check acceptance command: must PASS on a true earlier state and FAIL on a tampered one.

python synthetic/test_replay.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from itm.cli import main as itm  # noqa: E402

D = ROOT / "data"
fails = []


def run(baseline: dict) -> int:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(baseline, fh)
    try:
        itm(["--anchor", str(D / "anchor.json"), "--logs", str(D / "auditlogs.json"),
             "replay-check", "--baseline", fh.name])
    except SystemExit as e:
        return int(e.code or 0)
    return 0


def main():
    truth = json.loads((D / "truth.json").read_text())
    anchor = json.loads((D / "anchor.json").read_text())
    # a true earlier state (after the silent deletion, so no pre-window-only edges are involved)
    cp = next(c for c in truth["checkpoints"] if c["time"].startswith("2026-09-20T01:00"))
    base = {"captured_at": cp["time"], "tenant_id": anchor.get("tenant_id"), "objects": anchor["objects"],
            "edges": [{"type": t, "src": s, "dst": d} for t, s, d in cp["edges"]]}
    print("== true baseline (expect PASS)")
    ok_true = run(base) == 0
    print("\n== tampered baseline: one extra edge (expect FAIL)")
    bad = dict(base, edges=base["edges"] + [{"type": "member_of", "src": base["edges"][0]["src"],
                                              "dst": "00000000-0000-0000-0000-00000000dead"}])
    ok_bad = run(bad) == 1
    print(f"\n  [{'PASS' if ok_true else 'FAIL'}] replay-check passes on a true earlier state")
    print(f"  [{'PASS' if ok_bad else 'FAIL'}] replay-check fails on a tampered earlier state")
    fails.extend(n for n, ok in (("true", ok_true), ("tampered", ok_bad)) if not ok)
    print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
