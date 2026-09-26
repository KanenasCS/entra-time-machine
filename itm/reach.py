"""Reachability over the reconstructed graph.

Window queries are evaluated at every change point inside the window and the
results are unioned. They are NOT computed on the union of all edges seen in the
window, because that invents paths whose edges never co-existed (see naive_union_reach).
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

from .model import (ACTOR_TYPES, CREDENTIAL, HAS_ROLE, TIER0_ROLES, fmt_time,
                    min_conf, role_node)
from .timeline import Timeline

TIER0_NODES = {role_node(t): n for t, n in TIER0_ROLES.items()}


@dataclass
class Span:
    start: datetime
    end: datetime
    path: list          # list of (src, dst, Interval)
    open_start: bool    # already present at window start
    open_end: bool      # still present at window end

    @property
    def confidence(self) -> str:
        return min_conf(*[iv.confidence for _, _, iv in self.path]) if self.path else "high"

    @property
    def via_pim(self) -> bool:
        return any(iv.pim for _, _, iv in self.path)


def _adjacency(intervals, reverse=False):
    adj = defaultdict(list)
    for iv in intervals:
        e = iv.edge
        src = iv.holder if e.type == CREDENTIAL else e.src
        if not src:
            continue  # key with unknown holder: cannot attribute control
        if reverse:
            adj[e.dst].append((src, iv))
        else:
            adj[src].append((e.dst, iv))
    return adj


def reach_from(principal: str, intervals) -> dict:
    """node -> path (list of (src, dst, interval)) for every node reachable from principal."""
    adj = _adjacency(intervals)
    paths = {principal: []}
    q = deque([principal])
    while q:
        n = q.popleft()
        for dst, iv in adj.get(n, ()):
            if dst not in paths:
                paths[dst] = paths[n] + [(n, dst, iv)]
                q.append(dst)
    paths.pop(principal)
    return paths


def who_reaches(target: str, intervals) -> dict:
    """source node -> path to target, for every node that can reach target."""
    radj = _adjacency(intervals, reverse=True)
    paths = {target: []}
    q = deque([target])
    while q:
        n = q.popleft()
        for src, iv in radj.get(n, ()):
            if src not in paths:
                paths[src] = [(src, n, iv)] + paths[n]
                q.append(src)
    paths.pop(target)
    return paths


def _is_actor(tl: Timeline, node: str) -> bool:
    return (tl.objects.get(node) or {}).get("type") in ACTOR_TYPES


def tier0_pairs(tl: Timeline, intervals) -> dict:
    """(actor, tier0 role node) -> path."""
    out = {}
    for role in TIER0_NODES:
        for src, path in who_reaches(role, intervals).items():
            if _is_actor(tl, src):
                out[(src, role)] = path
    return out


def _track(cps, t2, present_at):
    open_, spans = {}, defaultdict(list)
    for i, cp in enumerate(cps):
        cur = present_at(cp)
        for k, path in cur.items():
            if k not in open_:
                open_[k] = (cp, path, i == 0)
        for k in [k for k in open_ if k not in cur]:
            s, path, os_ = open_.pop(k)
            spans[k].append(Span(s, cp, path, os_, False))
    for k, (s, path, os_) in open_.items():
        spans[k].append(Span(s, t2, path, os_, True))
    return spans


def window_reach(tl: Timeline, principal: str, t1: datetime, t2: datetime, roles_only=True) -> dict:
    """node -> [Span] for everything the principal could reach at any moment in [t1, t2)."""
    def present(cp):
        r = reach_from(principal, tl.active_at(cp))
        return {n: p for n, p in r.items() if not roles_only or p[-1][2].edge.type == HAS_ROLE}
    return _track(tl.change_points(t1, t2), t2, present)


def ephemeral_tier0(tl: Timeline, t1: datetime, t2: datetime) -> dict:
    """(actor, role) -> [Span] for tier-0 reach that existed inside the window but not at the anchor."""
    at_anchor = set(tier0_pairs(tl, tl.active_at(tl.anchor_time)))
    spans = _track(tl.change_points(t1, t2), t2, lambda cp: tier0_pairs(tl, tl.active_at(cp)))
    return {k: v for k, v in spans.items() if k not in at_anchor}


def naive_union_reach(tl: Timeline, principal: str, t1: datetime, t2: datetime) -> dict:
    """WRONG ON PURPOSE: reachability over every edge that existed at any point in the window."""
    r = reach_from(principal, tl.overlapping(t1, t2))
    return {n: p for n, p in r.items() if p[-1][2].edge.type == HAS_ROLE}


def format_path(tl: Timeline, path) -> str:
    if not path:
        return "(direct)"
    parts = [tl.name(path[0][0])]
    for src, dst, iv in path:
        label = iv.edge.type
        if iv.edge.type == CREDENTIAL:
            label = f"holds {iv.edge.src[4:12]}.."
        if iv.pim:
            label += " [PIM]"
        parts.append(f"-{label}-> {tl.name(dst)}")
    return " ".join(parts)


def format_span(s: Span) -> str:
    a = ("<=" if s.open_start else "") + fmt_time(s.start)
    b = fmt_time(s.end) + ("+" if s.open_end else "")
    return f"{a} .. {b}"
