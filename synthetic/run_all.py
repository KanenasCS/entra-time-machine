"""Run the full offline test suite.

python synthetic/run_all.py
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
steps = [("generate synthetic tenant", "generate.py"), ("engine accuracy report", "evaluate.py"),
         ("collector round-trip", "test_collector.py"), ("foreign principals", "test_foreign.py"),
         ("replay-check acceptance command", "test_replay.py")]
results = []
for label, script in steps:
    r = subprocess.run([sys.executable, str(HERE / script)], capture_output=True, text=True)
    ok = r.returncode == 0
    results.append((label, ok))
    tail = [ln for ln in r.stdout.splitlines() if ln.startswith(("ALL ", "EPHEMERAL", "RESULT", "rows="))]
    print(f"[{'PASS' if ok else 'FAIL'}] {label}")
    for ln in tail:
        print("       " + ln)
    if not ok:
        print(r.stdout[-2000:], r.stderr[-2000:])
print("\nSUITE:", "ALL PASS" if all(ok for _, ok in results) else "FAILURES")
sys.exit(0 if all(ok for _, ok in results) else 1)
