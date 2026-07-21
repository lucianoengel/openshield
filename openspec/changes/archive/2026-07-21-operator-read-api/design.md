## Context

The control plane already serves `/enroll` (agent role) and `/view` (operator role)
over mutual TLS with cert-role authorization (`requireRole`, D56/D58), and derives the
operator identity from the verified client cert (D47). `Server.Overdue` (dead-man's-
switch, D50/D51) and the `peer_alerts` table (peer-UEBA, D54) exist but nothing reads
them outside tests.

## Goals / Non-Goals

**Goals:** an operator-authenticated read API over peer alerts and overdue agents;
reuse the existing role gate; read-only.

**Non-Goals:** a UI; an operator-read audit row for aggregate reads; pagination
beyond limit; a telemetry search API.

## Decisions

**Reuse the operator role gate, add read-only routes.** `/alerts` and `/overdue` mount
behind `requireRole(RoleOperator)` in `ServeHTTPTLS`, the same gate `/view` uses — an
unauthenticated request gets 401, an agent cert 403, an operator cert 200. The
endpoints hold no signer and can forge nothing (the D30 read/write asymmetry that lets
`openshieldctl` and now these run for a reader without threatening the evidence).

**Return JSON of pseudonymous, boundary-safe fields.** A peer alert carries the
pseudonymous subject, risk score, context version, timestamp (D23) — no content. An
overdue agent carries the agent id, last-seen, silence. Both are aggregate detection
surfaces (D38/D54), safe for an operator to read; the subject is a pseudonym, mapped to
a real identity only through a separate audited lookup (D23).

**Thresholds are query params with sane defaults.** `/overdue?threshold=15m` and
`/alerts?limit=100` — a coarse read control, not a query language. A richer search API
is a noted follow-up.

## Risks / Trade-offs

- **No operator-read audit for aggregate reads.** `/view` records who viewed a
  per-subject investigation (D47); these aggregate fleet reads do not yet write a view
  row. Recording them for symmetry is a noted follow-up; the operator identity is still
  authenticated per request, so the read is not anonymous, just not persisted.
- **Reads are point-in-time, unpaginated beyond a limit.** Fine for a monitoring
  surface; a real console needs paging/filtering, noted.
