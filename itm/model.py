"""Core data model for Identity Time Machine."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

# Edge types. Direction is always "src gains the power of dst".
MEMBER_OF = "member_of"    # principal/group -> group
HAS_ROLE = "has_role"      # principal/group -> role:<templateId>
OWNS = "owns"              # user/sp -> application or service principal
CREDENTIAL = "credential"  # key:<keyId> -> application or service principal (holder kept as attribute)
BACKS = "backs"            # application -> its service principal (static, from anchor)

EDGE_TYPES = (MEMBER_OF, HAS_ROLE, OWNS, CREDENTIAL, BACKS)

# Built-in role template IDs treated as tier-0. Extend as needed.
TIER0_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
}

# Assumed PIM activation length when neither an expiry event nor an expiry time is logged.
DEFAULT_PIM_DURATION = timedelta(hours=8)

ACTOR_TYPES = {"User", "ServicePrincipal", "ForeignPrincipal"}
CONF_RANK = {"high": 3, "medium": 2, "low": 1}


def role_node(template_id: str) -> str:
    return f"role:{template_id.lower()}"


def key_node(key_id: str) -> str:
    return f"key:{key_id.lower()}"


def min_conf(*confs: str) -> str:
    return min(confs, key=lambda c: CONF_RANK[c])


_FRAC = re.compile(r"\.(\d+)")


def parse_time(value: str) -> datetime:
    """Parse ISO timestamps, including Log Analytics 7-digit fractions and a trailing Z."""
    v = value.strip().replace("Z", "+00:00")
    v = _FRAC.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), v, count=1)
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_time(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else "-"


@dataclass(frozen=True, order=True)
class EdgeKey:
    type: str
    src: str
    dst: str


@dataclass
class Delta:
    """One edge change extracted from an audit event."""
    time: datetime
    action: str  # "add" | "remove"
    edge: EdgeKey
    source_op: str
    event_id: str
    seq: int = 0
    initiator: Optional[str] = None
    pim: bool = False
    pim_expires: Optional[datetime] = None
    holder: Optional[str] = None  # credential edges only: who added the key


@dataclass
class ObjectDeletion:
    time: datetime
    object_id: str
    source_op: str
    event_id: str
    seq: int = 0


@dataclass
class Interval:
    """A span during which an edge existed. start None = existed before the log window.
    end None = still present at the anchor."""
    edge: EdgeKey
    start: Optional[datetime]
    end: Optional[datetime]
    confidence: str
    notes: list = field(default_factory=list)
    start_event: Optional[str] = None
    end_event: Optional[str] = None
    pim: bool = False
    holder: Optional[str] = None

    def active_at(self, t: datetime) -> bool:
        return (self.start is None or self.start <= t) and (self.end is None or t < self.end)

    def overlaps(self, t1: datetime, t2: datetime) -> bool:
        return (self.start is None or self.start < t2) and (self.end is None or self.end > t1)


@dataclass
class Anchor:
    captured_at: datetime
    objects: dict  # id -> {"type":..., "displayName":..., ...}
    edges: set     # set[EdgeKey]
    holders: dict  # key node -> holder id, when known
    tenant_id: Optional[str] = None

    @classmethod
    def load(cls, path: str) -> "Anchor":
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        edges, holders = set(), {}
        for e in raw["edges"]:
            ek = EdgeKey(e["type"], e["src"].lower(), e["dst"].lower())
            edges.add(ek)
            if e.get("holder"):
                holders[ek.src] = e["holder"].lower()
        objects = {k.lower(): v for k, v in raw["objects"].items()}
        tid = (raw.get("tenant_id") or "").lower() or None
        return cls(parse_time(raw["captured_at"]), objects, edges, holders, tid)


# Microsoft Graph application permissions that let a service principal take over the tenant,
# directly or in one step. Treated as tier-0 equivalents once app role edges are modeled.
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
TIER0_GRAPH_APP_ROLES = {
    "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All",
    "Directory.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All", "Domain.ReadWrite.All",
    "Policy.ReadWrite.PermissionGrant", "RoleAssignmentSchedule.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory", "PrivilegedAccess.ReadWrite.AzureADGroup",
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup", "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
    "Policy.ReadWrite.AuthenticationMethod", "Organization.ReadWrite.All",
}
