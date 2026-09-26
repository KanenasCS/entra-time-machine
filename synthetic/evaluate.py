"""Score the engine against synthetic ground truth.

python synthetic/evaluate.py
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from itm.model import Anchor, fmt_time, parse_time  # noqa: E402
from itm.parse import load_rows, parse_rows  # noqa: E402
from itm.reach import ephemeral_tier0, naive_union_reach, window_reach  # noqa: E402
from itm.timeline import build_timeline  # noqa: E402

D = ROOT / "data"


def main():
    truth = json.loads((D / "truth.json").read_text())
    anchor = Anchor.load(D / "anchor.json")
    parsed = parse_rows(load_rows(D / "auditlogs.json"))
    tl = build_timeline(anchor, parsed)
    names = truth["objects"]
    nm = lambda i: (names.get(i) or tl.objects.get(i) or {}).get("displayName") or i  # noqa: E731

    # 1. edge-level accuracy at every checkpoint
    tp, fp, fn = Counter(), Counter(), Counter()
    fn_examples, fp_examples = defaultdict(set), defaultdict(set)
    for cp in truth["checkpoints"]:
        t = parse_time(cp["time"])
        true_e = {tuple(e) for e in cp["edges"]}
        got = {(iv.edge.type, iv.edge.src, iv.edge.dst) for iv in tl.active_at(t)}
        for e in true_e & got:
            tp[e[0]] += 1
        for e in got - true_e:
            fp[e[0]] += 1
            fp_examples[e].add(t)
        for e in true_e - got:
            fn[e[0]] += 1
            fn_examples[e].add(t)

    print(f"EDGE ACCURACY over {len(truth['checkpoints'])} checkpoints")
    print(f"{'type':<11} {'precision':>9} {'recall':>7}   tp/fp/fn")
    for typ in sorted(set(tp) | set(fp) | set(fn)):
        p = tp[typ] / max(1, tp[typ] + fp[typ])
        r = tp[typ] / max(1, tp[typ] + fn[typ])
        print(f"{typ:<11} {p:>9.4f} {r:>7.4f}   {tp[typ]}/{fp[typ]}/{fn[typ]}")
    T, F, N = sum(tp.values()), sum(fp.values()), sum(fn.values())
    print(f"{'ALL':<11} {T / (T + F):>9.4f} {T / (T + N):>7.4f}   {T}/{F}/{N}")
    for label, ex in (("false positives", fp_examples), ("false negatives", fn_examples)):
        if ex:
            print(f"\n{label} (distinct edges):")
            for e, ts in sorted(ex.items()):
                print(f"  {e[0]:<10} {nm(e[1])} -> {nm(e[2])}   {len(ts)} checkpoints, "
                      f"{fmt_time(min(ts))} .. {fmt_time(max(ts))}")

    # 2. ephemeral tier-0 detection
    t1, t2 = parse_time(truth["window_start"]), parse_time(truth["anchor"])
    got = ephemeral_tier0(tl, t1, t2)
    true_pairs = {(e["actor"], e["role"]): e["spans"] for e in truth["ephemeral_tier0"]}
    print(f"\nEPHEMERAL TIER-0 PATHS: truth={len(true_pairs)} found={len(got)} "
          f"missed={len(set(true_pairs) - set(got))} spurious={len(set(got) - set(true_pairs))}")
    for k in sorted(set(true_pairs) | set(got), key=lambda k: nm(k[0])):
        ts = [(parse_time(a), parse_time(b)) for a, b in true_pairs.get(k, [])]
        gs = [(s.start, s.end) for s in got.get(k, [])]
        status = "MISSED" if k not in got else "SPURIOUS" if k not in true_pairs else "found"
        print(f"  [{status:<8}] {nm(k[0])} -> {nm(k[1])}")
        for i in range(max(len(ts), len(gs))):
            tv = ts[i] if i < len(ts) else None
            gv = gs[i] if i < len(gs) else None
            if tv and gv:
                ds = (gv[0] - tv[0]).total_seconds() / 3600
                de = (gv[1] - tv[1]).total_seconds() / 3600
                verdict = "exact" if ds == 0 and de == 0 else f"start {ds:+.1f}h end {de:+.1f}h"
                print(f"      true {fmt_time(tv[0])}..{fmt_time(tv[1])}  got {fmt_time(gv[0])}..{fmt_time(gv[1])}  {verdict}")
            else:
                print(f"      true {tv}  got {gv}")

    # 3. temporal trap: naive union graph vs change-point evaluation
    trap = truth["trap"]
    naive = trap["role"] in naive_union_reach(tl, trap["principal"], t1, t2)
    correct = trap["role"] in window_reach(tl, trap["principal"], t1, t2)
    print(f"\nTEMPORAL TRAP ({trap['note']})")
    print(f"  naive union graph says {nm(trap['principal'])} reached GA: {naive}   (truth: False)")
    print(f"  change-point engine says:                     {correct}   (truth: False)")


if __name__ == "__main__":
    main()
