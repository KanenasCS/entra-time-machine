"""Identity Time Machine CLI.

python -m itm --anchor anchor.json --logs auditlogs.json <command> ...
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter

from .model import TIER0_ROLES, Anchor, fmt_time, parse_time, role_node
from .parse import load_rows, parse_rows
from .reach import (TIER0_NODES, ephemeral_tier0, format_path, format_span, human_duration,
                    naive_union_reach, reach_from, window_reach)
from .timeline import build_timeline


def resolve(tl, needle: str) -> str:
    n = needle.lower()
    if n in tl.objects:
        return n
    hits = [k for k, v in tl.objects.items()
            if n in ((v.get("displayName") or "").lower(), (v.get("userPrincipalName") or "").lower())]
    if len(hits) == 1:
        return hits[0]
    if not hits and len(n) >= 8:
        hits = [k for k in tl.objects if k.startswith(n)]
        if len(hits) == 1:
            return hits[0]
    sys.exit(f"could not resolve '{needle}' ({len(hits)} matches)")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="itm", description="Identity graph time machine for Entra ID")
    ap.add_argument("--anchor", required=True, help="anchor snapshot JSON (graph state now)")
    ap.add_argument("--logs", required=True, help="AuditLogs export (JSON array or JSONL)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("summary", help="parse stats, window, conflicts")

    p = sub.add_parser("state-at", help="all edges present at a moment")
    p.add_argument("time")
    p.add_argument("--type")

    p = sub.add_parser("reach", help="what a principal could reach at a moment")
    p.add_argument("principal")
    p.add_argument("--at", required=True)

    p = sub.add_parser("window-reach", help="everything a principal could reach at any point in a window")
    p.add_argument("principal")
    p.add_argument("--from", dest="t1", required=True)
    p.add_argument("--to", dest="t2")
    p.add_argument("--naive", action="store_true", help="also show the (wrong) union-graph answer")

    p = sub.add_parser("ephemeral", help="tier-0 reach that existed in the window but not now")
    p.add_argument("--from", dest="t1", required=True)
    p.add_argument("--to", dest="t2")
    p.add_argument("--hide-pim", action="store_true")

    sub.add_parser("foreign", help="roles held by principals outside this directory, over time")

    p = sub.add_parser("replay-check", help="acceptance test: rebuild an earlier anchor from this one plus the logs")
    p.add_argument("--baseline", required=True, help="an EARLIER anchor snapshot to reproduce")

    p = sub.add_parser("history", help="every interval touching an object")
    p.add_argument("object")

    a = ap.parse_args(argv)
    anchor = Anchor.load(a.anchor)
    parsed = parse_rows(load_rows(a.logs))
    tl = build_timeline(anchor, parsed)

    if a.cmd == "summary":
        print(f"anchor         {fmt_time(tl.anchor_time)}")
        print(f"log window     {fmt_time(tl.earliest_event)} .. {fmt_time(tl.anchor_time)}")
        print(f"deltas         {len(parsed.deltas)}   deletions {len(parsed.deletions)}   "
              f"duplicates dropped {parsed.duplicates_dropped}")
        print(f"intervals      {len(tl.intervals)}   " +
              "  ".join(f"{k}={v}" for k, v in Counter(iv.confidence for iv in tl.intervals).items()))
        print(f"skipped ops    {sum(parsed.skipped.values())}   parse errors {len(parsed.errors)}")
        for e in parsed.errors[:10]:
            print("  ERR", e)
        print(f"foreign        {len(tl.foreign_principals())} principals outside this directory hold roles")
        print(f"conflicts      {len(tl.conflicts)}")
        for c in tl.conflicts:
            print("  !", c)
        return

    if a.cmd == "state-at":
        t = parse_time(a.time)
        _warn_window(tl, t)
        for iv in sorted(tl.active_at(t), key=lambda iv: iv.edge):
            if a.type and iv.edge.type != a.type:
                continue
            src = tl.name(iv.holder) + f" (key {iv.edge.src[4:12]}..)" if iv.edge.type == "credential" else tl.name(iv.edge.src)
            print(f"{iv.edge.type:<11} {src} -> {tl.name(iv.edge.dst)}   [{iv.confidence}]")
        return

    if a.cmd == "reach":
        t = parse_time(a.at)
        _warn_window(tl, t)
        who = resolve(tl, a.principal)
        roles = {n: p for n, p in reach_from(who, tl.active_at(t)).items() if n.startswith("role:")}
        if not roles:
            print("no roles reachable")
        for node, path in sorted(roles.items(), key=lambda x: len(x[1])):
            if True:
                tag = "TIER0 " if node in TIER0_NODES else ""
                print(f"{tag}{tl.name(node)}\n    {format_path(tl, path)}")
        return

    if a.cmd == "window-reach":
        t1 = parse_time(a.t1)
        t2 = parse_time(a.t2) if a.t2 else tl.anchor_time
        _warn_window(tl, t1)
        who = resolve(tl, a.principal)
        res = window_reach(tl, who, t1, t2)
        if not res:
            print("no roles reachable at any point in the window")
        for node, spans in res.items():
            tag = "TIER0 " if node in TIER0_NODES else ""
            print(f"{tag}{tl.name(node)}")
            for s in spans:
                print(f"    {format_span(s)}  [{s.confidence}]  {format_path(tl, s.path)}")
        if a.naive:
            extra = set(naive_union_reach(tl, who, t1, t2)) - set(res)
            print("\nnaive union-graph would ALSO claim (false paths):")
            for n in extra or ["(none)"]:
                print("   ", tl.name(n) if n != "(none)" else n)
        return

    if a.cmd == "ephemeral":
        t1 = parse_time(a.t1)
        t2 = parse_time(a.t2) if a.t2 else tl.anchor_time
        _warn_window(tl, t1)
        res = ephemeral_tier0(tl, t1, t2)
        rows = []
        for (actor, role), spans in res.items():
            for s in spans:
                if a.hide_pim and s.via_pim:
                    continue
                rows.append((s.start, actor, role, s))
        if not rows:
            print("no ephemeral tier-0 paths in window")
        for _, actor, role, s in sorted(rows):
            flag = " PIM" if s.via_pim else ""
            print(f"{tl.name(actor)} -> {tl.name(role)}  {format_span(s)}  ({human_duration(s)})  [{s.confidence}{flag}]")
            print(f"    {format_path(tl, s.path)}")
        return

    if a.cmd == "foreign":
        fps = tl.foreign_principals()
        if not fps:
            print("no foreign principals")
        for fp in sorted(fps):
            o = tl.objects[fp]
            ivs = sorted((iv for iv in tl.intervals if iv.edge.type == "has_role" and iv.edge.src == fp),
                         key=lambda iv: (iv.edge.dst not in TIER0_NODES, tl.name(iv.edge.dst)))
            t0 = sum(1 for iv in ivs if iv.edge.dst in TIER0_NODES)
            print(f"{tl.name(fp)}  id={fp}  tenant={o.get('principalTenantId') or 'unknown'}  "
                  f"seen-as={o.get('observedType') or 'unknown'}  roles={len(ivs)}  tier0={t0}")
            for iv in ivs:
                tag = "TIER0 " if iv.edge.dst in TIER0_NODES else "      "
                start = fmt_time(iv.start) if iv.start else "<window"
                end = fmt_time(iv.end) if iv.end else "now"
                print(f"   {tag}{tl.name(iv.edge.dst):<45} {start:<20} .. {end:<20} [{iv.confidence}]")
        return

    if a.cmd == "replay-check":
        base = Anchor.load(a.baseline)
        if base.captured_at >= tl.anchor_time:
            sys.exit("baseline must be captured BEFORE the --anchor snapshot")
        if tl.earliest_event and base.captured_at < tl.earliest_event:
            print("WARNING: baseline predates the log window; edges changed before the window cannot be rebuilt")
        got = {iv.edge for iv in tl.active_at(base.captured_at)}
        exp = set(base.edges)
        missing, extra = exp - got, got - exp
        print(f"replaying {fmt_time(tl.anchor_time)} back to {fmt_time(base.captured_at)}")
        print(f"{'type':<11} {'baseline':>8} {'rebuilt':>8} {'missing':>8} {'extra':>6}")
        for typ in sorted({e.type for e in exp | got}):
            print(f"{typ:<11} {sum(e.type == typ for e in exp):>8} {sum(e.type == typ for e in got):>8} "
                  f"{sum(e.type == typ for e in missing):>8} {sum(e.type == typ for e in extra):>6}")
        nm = lambda i: tl.name(i) if i in tl.objects else (base.objects.get(i) or {}).get("displayName") or i  # noqa: E731
        for label, es in (("missing", missing), ("extra", extra)):
            for e in sorted(es)[:20]:
                print(f"  {label:<7} {e.type:<11} {nm(e.src)} -> {nm(e.dst)}")
        ok = not missing and not extra
        print("RESULT:", "PASS" if ok else "FAIL")
        sys.exit(0 if ok else 1)

    if a.cmd == "history":
        obj = resolve(tl, a.object)
        for iv in tl.history(obj):
            src = tl.name(iv.holder) if iv.edge.type == "credential" else tl.name(iv.edge.src)
            print(f"{fmt_time(iv.start) if iv.start else '<window':<20} .. {fmt_time(iv.end) if iv.end else 'now':<20} "
                  f"{iv.edge.type:<11} {src} -> {tl.name(iv.edge.dst)}  [{iv.confidence}] {'; '.join(iv.notes)}")


def _warn_window(tl, t):
    if tl.earliest_event and t < tl.earliest_event:
        print(f"WARNING: {fmt_time(t)} is before the log window ({fmt_time(tl.earliest_event)}). "
              "Only edges from the anchor with unknown start are shown.", file=sys.stderr)
