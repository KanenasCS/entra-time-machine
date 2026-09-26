# How it works

## Model

The identity graph is a set of directed edges. Direction always means *the source gains the power of the destination*.

| Edge | Meaning |
|---|---|
| `member_of` | User, group or service principal is a member of a group |
| `has_role` | Principal or group holds a directory role at tenant scope |
| `owns` | User or service principal owns an application or service principal |
| `credential` | A secret or certificate exists on an application or service principal, attributed to whoever added it |
| `backs` | An application registration backs its service principal |

Controlling an application (as owner or through a credential) grants control of its service principal and therefore that service principal's roles.

## Reverse replay

The snapshot (anchor) is the state of the graph at capture time. Audit events are processed from newest to oldest:

* Undoing an **add** closes an interval: the edge started at that event.
* Undoing a **removal** opens an interval: the edge existed before that event.
* Edges still open when the oldest event is reached existed before the log window.

Because the anchor is taken from the live tenant, the approach works against existing log history on day one. No prior collection is needed.

## Unlogged removals

Some changes end without a matching removal event. For example, deleting a user silently removes all of its memberships. When an add has no matching removal, the end is inferred in this order:

| Evidence | Confidence |
|---|---|
| Deletion of either endpoint after the add | medium |
| PIM activation expiry time recorded on the activation | medium |
| The next logged add of the same edge | low |
| The default PIM activation length (8 hours) | low |
| Otherwise: assumed present until the anchor | low |

The last rule is deliberately conservative. In an investigation, overstating possible access is safer than missing it.

## Duplicate audit rows

Entra can write the same change more than once. Repeats of the same action on the same edge (or deletion of the same object) within 60 seconds, with no opposite action between them, are collapsed. Without this step each copy would look like an add with no matching removal and produce an invented interval.

## Temporally correct reachability

Reachability over a window is evaluated at every moment the graph changed, and the results are combined. It is never computed on the union of every edge seen in the window, because edges that never co-existed would form paths that never existed. `window-reach --naive` prints what the union approach would wrongly claim.

## Foreign principals

A principal is typed `ForeignPrincipal` when any of the following holds:

1. The collector found it holding a role but could not find it in the directory.
2. Its `Principal Tenant ID` in role events differs from the home tenant.
3. It holds a role in the anchor and appears in none of the anchor's object lists.
4. It appears in role events, is absent from the directory, and was never deleted.

The home tenant comes from the anchor. For anchors that lack it, it is inferred from role events of principals that do exist in the directory. Foreign principals count as actors in every report.

## Collector

The collector reads users, groups, applications, service principals, direct group members, owners, credentials and tenant-scoped role assignments. Role assignments are read both as a full listing and per role definition, and the results are combined. Members and owners are fetched through `$batch` (20 requests per call). Paging, throttling (429, 503, 504 with `Retry-After`) and a single token refresh are handled.

Owners of Microsoft first-party service principals are skipped unless `--all-sp-owners` is set. Scoped role assignments (administrative units, app scopes) and non-actor group members (devices, contacts) are skipped and counted in the output.

The snapshot is not atomic. `captured_at` is the start of collection, and changes made during collection may surface as conflicts.
