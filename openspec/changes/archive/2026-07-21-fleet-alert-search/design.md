## Context

D82 gave a fixed "recent alerts" read. Investigation needs filtering. The rows already
exist in peer_alerts; F1 is a query surface over them.

## Goals / Non-Goals

**Goals:** filter fleet alerts by subject/risk/time as parameterized SQL, behind the
operator gate.

**Non-Goals:** content search (there is no content); correlation; casework; UI.

## Decisions

**Parameterized, constraint-by-constraint.** The WHERE clause is assembled from only the
filter fields that are set, each value appended to the args and bound as `$N` — operator
input is never concatenated into SQL. The test drives an injection-shaped subject through
the API and asserts the table is intact, so the property is proven, not asserted.

**Search the aggregate, not evidence.** Peer alerts are the control plane's own
fleet-derivation (D54), content-free and pseudonymous (D23); F1 searches them. Full-text
search over event payloads is out of scope because there are no payloads to search — the
boundary rule (D10/D29) keeps content on the endpoints.

## Risks / Trade-offs

- **Filter set is deliberately small** (subject/risk/time). It is the useful core; more
  facets (context_version, host) are trivial additions on the same parameterized pattern.
- **No pagination cursor yet** — a limit only. Fine for the current fleet scale; a cursor
  is a follow-up when result sets grow.
