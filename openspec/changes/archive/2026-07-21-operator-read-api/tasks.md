# Tasks — operator read API (D82)

## 1. Read query

- [x] 1.1 `PeerAlert` struct (SubjectID, RiskScore, ContextVersion, DetectedAt); `Server.RecentPeerAlerts(ctx, limit int) ([]PeerAlert, error)` — SELECT ... FROM peer_alerts ORDER BY detected_at DESC LIMIT.

## 2. Handler + wiring

- [x] 2.1 `Server.OperatorReadHandler() http.Handler` — mux: GET /alerts (RecentPeerAlerts JSON, ?limit= default 100); GET /overdue (Overdue(threshold, now) JSON, ?threshold= default 15m). Method-guarded, JSON-encoded.
- [x] 2.2 `ServeHTTPTLS`: mount /alerts and /overdue behind `requireRole(RoleOperator)`.

## 3. Proof (guards, each mutation-tested)

- [x] 3.1 **Test** (real Postgres + operator-cert harness): insert a peer_alerts row + a stale heartbeat; operator GET /alerts returns the alert JSON; operator GET /overdue returns the overdue agent.
- [x] 3.2 **Test**: an agent-role cert gets 403 on /alerts and /overdue; an unauthenticated request gets 401.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D82: operator read API (/alerts, /overdue) behind the operator-role gate, read-only, wiring the dead-man's-switch and peer-UEBA to a reader — closing the "zero readers" gap.
- [x] 4.2 `openspec validate operator-read-api --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| read routes mounted without the operator role gate | `TestOperatorReadAPI` (agent not 403) |
| RecentPeerAlerts returns nothing (limit 0) | `TestOperatorReadAPI` (empty /alerts) |

THE VERDICT (D82): the operator has a read API — /alerts and /overdue — over the fleet aggregate,
behind the same mutual-TLS operator-role gate as /view, read-only and forge-nothing; the dead-man's-
switch and peer-UEBA are now reachable by a human. Still no UI (this is its API). NOT in scope: UI;
operator-read audit rows; pagination; search API.
