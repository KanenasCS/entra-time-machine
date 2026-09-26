"""Foreign-principal detection, asserted explicitly for new-style and old-style (v0.2.4) anchors.

python synthetic/test_foreign.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from itm.model import Anchor, parse_time  # noqa: E402
from itm.parse import load_rows, parse_rows  # noqa: E402
from itm.reach import ephemeral_tier0  # noqa: E402
from itm.timeline import build_timeline  # noqa: E402

D = ROOT / "data"
fails = []


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    if not ok:
        fails.append(name)


def run(label, anchor_path):
    truth = json.loads((D / "truth.json").read_text())
    foreign_ids = {k for k, v in truth["objects"].items() if v.get("foreign")}
    tl = build_timeline(Anchor.load(anchor_path), parse_rows(load_rows(D / "auditlogs.json")))
    fps = tl.foreign_principals()
    print(label)
    check("every true foreign principal typed ForeignPrincipal", foreign_ids <= fps,
          f"missing {sorted(i[:8] for i in foreign_ids - fps)}")
    check("no local principal typed foreign", fps <= foreign_ids,
          f"wrongly foreign {sorted(i[:8] for i in fps - foreign_ids)}")
    eph = ephemeral_tier0(tl, parse_time(truth["window_start"]), parse_time(truth["anchor"]))
    true_pairs = {(e["actor"], e["role"]) for e in truth["ephemeral_tier0"]}
    check("ephemeral tier-0 pairs match truth (incl. foreign)", set(eph) == true_pairs,
          f"truth={len(true_pairs)} found={len(eph)}")
    temp = [e for e in truth["ephemeral_tier0"] if e["actor"] in foreign_ids]
    check("temporary foreign tier-0 grant detected", all((e["actor"], e["role"]) in eph for e in temp) and temp)


def main():
    run("NEW-STYLE ANCHOR (tenant_id + ForeignPrincipal typing)", D / "anchor.json")
    a = json.loads((D / "anchor.json").read_text())
    a.pop("tenant_id", None)
    a["objects"] = {k: v for k, v in a["objects"].items() if v.get("type") != "ForeignPrincipal"}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(a, fh)
    run("OLD-STYLE ANCHOR (v0.2.4: no tenant_id, no typing)", fh.name)
    print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
