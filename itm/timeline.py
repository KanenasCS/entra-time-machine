"""Reverse replay: anchor (known state now) + audit deltas -> edge validity intervals.

Walk events newest to oldest. The anchor is ground truth at its capture time.
  inverting an ADD    closes an interval: the edge started at that event.
  inverting a REMOVE  opens an interval: the edge existed before that event.
When an ADD is found for an edge that is not currently open, a removal was never
logged. The end is then inferred, in priority order, from:
  1. deletion of either endpoint after the add          (medium)
  2. PIM expiry time from the activation event          (medium)
  3. the next logged start of the same edge             (low)
  4. default PIM duration for PIM activations           (low)
  5. the anchor time, i.e. assume present until now     (low, conservative)
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .model import (BACKS, DEFAULT_PIM_DURATION, HAS_ROLE, Anchor, Interval,
                    ObjectDeletion, fmt_time)
from .parse import ParsedLog


@dataclass
class _Open:
    end: Optional[datetime]
    end_event: Optional[str]
    conf: str
    notes: list
    pim: bool = False
    holder: Optional[str] = None


@dataclass
class Timeline:
    anchor_time: datetime
    earliest_event: Optional[datetime]
    intervals: list
    objects: dict
    conflicts: list = field(default_factory=list)
    ignored_after_anchor: int = 0

    def active_at(self, t: datetime) -> list:
        return [iv for iv in self.intervals if iv.active_at(t)]

    def overlapping(self, t1: datetime, t2: datetime) -> list:
        return [iv for iv in self.intervals if iv.overlaps(t1, t2)]

    def change_points(self, t1: datetime, t2: datetime) -> list:
        pts = {t1}
        for iv in self.intervals:
            for p in (iv.start, iv.end):
                if p is not None and t1 < p < t2:
                    pts.add(p)
        return sorted(pts)

    def history(self, obj_id: str) -> list:
        obj_id = obj_id.lower()
        out = [iv for iv in self.intervals
               if obj_id in (iv.edge.src, iv.edge.dst) or iv.holder == obj_id]
        return sorted(out, key=lambda iv: (iv.start or datetime.min.replace(tzinfo=self.anchor_time.tzinfo)))

    def name(self, obj_id: Optional[str]) -> str:
        if not obj_id:
            return "unknown holder"
        o = self.objects.get(obj_id) or {}
        if o.get("type") == "ForeignPrincipal":
            return f"{o.get('displayName') or obj_id[:8]} (foreign)"
        return o.get("displayName") or obj_id

    def foreign_principals(self) -> set:
        return {k for k, v in self.objects.items() if v.get("type") == "ForeignPrincipal"}


def build_timeline(anchor: Anchor, parsed: ParsedLog) -> Timeline:
    objects = _merge_objects(anchor, parsed)

    events = sorted(parsed.deltas + parsed.deletions, key=lambda e: (e.time, e.seq), reverse=True)
    state: dict = {e: _Open(None, None, "high", ["present at anchor"], holder=anchor.holders.get(e.src))
                   for e in anchor.edges}
    intervals, conflicts = [], []
    deleted_at: dict = {}      # object id -> (time, event id) of earliest deletion seen so far after cursor
    next_start: dict = {}      # edge -> earliest start already recorded (later in time than cursor)
    ignored = 0

    for ev in events:
        if ev.time > anchor.captured_at:
            ignored += 1
            continue
        if isinstance(ev, ObjectDeletion):
            deleted_at[ev.object_id] = (ev.time, ev.event_id)
            continue

        d = ev
        if d.action == "add":
            o = state.pop(d.edge, None)
            if o is not None:
                intervals.append(Interval(d.edge, d.time, o.end, o.conf, list(o.notes),
                                          d.event_id, o.end_event, d.pim or o.pim, d.holder or o.holder))
            else:
                end, conf, note = _infer_end(d, deleted_at, next_start, anchor.captured_at)
                if conf == "low" and not d.pim:
                    conflicts.append(f"{fmt_time(d.time)} {d.source_op}: {d.edge.type} "
                                     f"{d.edge.src} -> {d.edge.dst} has no matching removal ({note})")
                intervals.append(Interval(d.edge, d.time, end, conf, [note], d.event_id, None, d.pim, d.holder))
            next_start[d.edge] = d.time
        else:  # remove
            o = state.pop(d.edge, None)
            if o is not None:
                # Present after this removal with no add in between: an unlogged re-add.
                conflicts.append(f"{fmt_time(d.time)} {d.source_op}: {d.edge.type} {d.edge.src} -> {d.edge.dst} "
                                 f"present after a logged removal with no add event")
                intervals.append(Interval(d.edge, d.time, o.end, "low",
                                          o.notes + ["re-added with no add event; start is a lower bound"],
                                          None, o.end_event, o.pim, o.holder))
                next_start[d.edge] = d.time
            state[d.edge] = _Open(d.time, d.event_id, "high", [], pim=d.pim)

    # Whatever is still open existed before the earliest event in the log window.
    for edge, o in state.items():
        notes = list(o.notes)
        if edge.type != BACKS:
            notes.append("start precedes log window")
        intervals.append(Interval(edge, None, o.end, o.conf, notes, None, o.end_event, o.pim, o.holder))

    earliest = min((e.time for e in events), default=None)
    return Timeline(anchor.captured_at, earliest, intervals, objects, conflicts, ignored)


def _infer_end(d, deleted_at, next_start, anchor_time):
    candidates = []
    for obj in (d.edge.src, d.edge.dst):
        if obj in deleted_at:
            t, eid = deleted_at[obj]
            candidates.append((t, "medium", f"end inferred from deletion of {obj} ({eid})"))
    if d.pim and d.pim_expires:
        candidates.append((d.pim_expires, "medium", "end taken from PIM activation expiry time"))
    if candidates:
        return min(candidates, key=lambda c: c[0])
    weak = []
    if d.edge in next_start:
        weak.append((next_start[d.edge], "low", "no removal logged; bounded by next logged add of the same edge"))
    if d.pim:
        weak.append((min(d.time + DEFAULT_PIM_DURATION, anchor_time), "low",
                     f"no PIM expiry logged; assumed default {DEFAULT_PIM_DURATION}"))
    if weak:
        return min(weak, key=lambda c: c[0])
    return anchor_time, "low", "no removal logged; assumed present until anchor (conservative)"


def _merge_objects(anchor: Anchor, parsed: ParsedLog) -> dict:
    """Anchor wins for local objects. A principal is ForeignPrincipal when:
      1. the collector typed it so, or
      2. it holds a role at the anchor but is in none of the anchor's object lists, or
      3. its Principal Tenant ID (from role events) differs from the home tenant, or
      4. it appears in role events, is absent from the anchor's object lists, and was never deleted.
    The home tenant comes from the anchor, or for older anchors is inferred as the most common
    Principal Tenant ID among role events whose principal IS in the anchor's object lists."""
    objects = {k: dict(v) for k, v in parsed.objects_seen.items()}

    def make_foreign(k, note=None):
        v = objects.setdefault(k, {"displayName": None})
        if v.get("type") != "ForeignPrincipal":
            v["observedType"] = v.get("type")
            v["type"] = "ForeignPrincipal"
        if note:
            v.setdefault("note", note)

    for k, v in anchor.objects.items():
        if v.get("type") == "ForeignPrincipal":
            base = objects.get(k, {})
            merged = dict(base)
            merged.update({kk: vv for kk, vv in v.items() if vv is not None})
            merged["observedType"] = base.get("type")
            merged["type"] = "ForeignPrincipal"
            objects[k] = merged
        else:
            objects[k] = dict(v)

    for e in anchor.edges:  # rule 2
        if e.type == HAS_ROLE and e.src not in anchor.objects:
            make_foreign(e.src, "holds a role but is not in the directory")

    deleted = {x.object_id for x in parsed.deletions}
    for d in parsed.deltas:  # rule 4: role principal absent from the directory and never deleted in window
        if d.edge.type == HAS_ROLE and d.edge.src not in anchor.objects and d.edge.src not in deleted:
            make_foreign(d.edge.src, "role principal absent from directory, no deletion logged")

    home = anchor.tenant_id
    if not home:
        votes = Counter(v["principalTenantId"] for k, v in parsed.objects_seen.items()
                        if v.get("principalTenantId") and k in anchor.objects
                        and anchor.objects[k].get("type") != "ForeignPrincipal")
        home = votes.most_common(1)[0][0] if votes else None
    if home:  # rule 3
        for k, v in list(objects.items()):
            t = v.get("principalTenantId")
            if t and t != home:
                make_foreign(k, "principal tenant differs from home tenant")
    return objects
