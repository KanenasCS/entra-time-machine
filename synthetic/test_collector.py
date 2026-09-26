"""Collector round-trip test (offline).

python synthetic/test_collector.py

1. Collect from the fake Graph (paging, throttling, expired token, noise objects).
2. The collected anchor must contain exactly the true edges at the anchor time.
3. The engine run on the collected anchor must find the same ephemeral tier-0 paths as the truth.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT), str(HERE)]

from fake_graph import EXPIRED, FakeGraph  # noqa: E402
from generate import ANCHOR  # noqa: E402

from itm.collect import GraphClient, collect  # noqa: E402
from itm.model import Anchor, parse_time  # noqa: E402
from itm.parse import load_rows, parse_rows  # noqa: E402
from itm.reach import ephemeral_tier0  # noqa: E402
from itm.timeline import build_timeline  # noqa: E402

D = ROOT / "data"
failures = []


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    if not ok:
        failures.append(name)


def main():
    fg = FakeGraph(page_size=3)
    tokens = iter([EXPIRED, "good-token", "good-token"])
    client = GraphClient(lambda: next(tokens), transport=fg.transport, sleep=lambda s: None)
    collected = collect(client, clock=lambda: ANCHOR)
    out = D / "anchor_collected.json"
    out.write_text(json.dumps(collected, indent=1))
    c = collected["collection"]

    print("COLLECTOR")
    print(f"  graph calls {c['graph_calls']}  throttled {c['throttled']}  token refreshes {c['token_refreshes']}")
    print(f"  objects {c['object_counts']}")
    print(f"  edges   {c['edge_counts']}")
    for w in c["warnings"]:
        print(f"  warn    {w}")

    expected = json.loads((D / "anchor.json").read_text())
    exp_edges = {(e["type"], e["src"], e["dst"]) for e in expected["edges"]}
    got_edges = {(e["type"], e["src"], e["dst"]) for e in collected["edges"]}
    foreign = ("has_role", fg.foreign_group, "role:" + fg.foreign_ra["roleDefinitionId"])
    check("per-role queries recover assignments missing from the unfiltered listing", foreign in got_edges
          and len(c["per_role_only"]) == 2, f"per_role_only={len(c['per_role_only'])}")
    check("foreign principals typed ForeignPrincipal",
          collected["objects"].get(fg.foreign_group, {}).get("type") == "ForeignPrincipal")
    check("tenant id recorded", collected.get("tenant_id") == expected.get("tenant_id"))
    got_edges.discard(foreign)
    check("collected edges == true anchor edges", exp_edges == got_edges,
          f"missing {len(exp_edges - got_edges)}, extra {len(got_edges - exp_edges)}")
    for e in sorted(exp_edges - got_edges)[:5]:
        print("     missing", e)
    for e in sorted(got_edges - exp_edges)[:5]:
        print("     extra  ", e)
    check("all true objects collected", set(expected["objects"]) <= set(collected["objects"]))
    check("expired token refreshed", c["token_refreshes"] == 1)
    check("direct and batch 429 both retried", c["throttled"] >= 2, f"throttled={c['throttled']}")
    check("paging followed (nextLink)", fg.calls["/users"] > 2, f"/users calls={fg.calls['/users']}")
    check("first-party SP owners not queried", not fg.forbidden_hits)
    check("device member skipped", c["skipped_member_types"].get("#microsoft.graph.device") == 1)
    check("scoped role assignment skipped", any("scoped role" in w for w in c["warnings"]))

    print("ENGINE ON COLLECTED ANCHOR")
    truth = json.loads((D / "truth.json").read_text())
    tl = build_timeline(Anchor.load(out), parse_rows(load_rows(D / "auditlogs.json")))
    got = ephemeral_tier0(tl, parse_time(truth["window_start"]), parse_time(truth["anchor"]))
    true_pairs = {(e["actor"], e["role"]) for e in truth["ephemeral_tier0"]}
    check("ephemeral tier-0 pairs match truth", set(got) == true_pairs,
          f"truth={len(true_pairs)} found={len(got)}")
    check("no replay conflicts", not tl.conflicts, f"{len(tl.conflicts)} conflicts")

    print("\nRESULT:", "ALL PASS" if not failures else f"{len(failures)} FAILED")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
