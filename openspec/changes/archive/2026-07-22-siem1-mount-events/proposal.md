# SIEM-1 REOPEN: mount /events on the served TLS mux

## Why

The event search (D132) registered its `/events` handler on the OperatorReadHandler's inner mux
but the server's TLS mux (`serve()` in `enroll_http.go`) never mounted it — it mounts
`/alerts`, `/alerts/ack`, `/search`, `/incidents`, `/overdue`, `/subject`, but not `/events`. So an
operator GET `/events` **404s in production**, even though the search logic is correct. The D132
tests exercised `SearchTelemetry`/`parseEventFilter` directly and never the served router — the
"verifies against its own assumptions" trap the project exists to avoid.

## What Changes

- **Mount `/events` on the served TLS mux**, behind the same operator-role gate as the other
  operator-read routes (one line in `serve()`).
- **A served-mux test** that hits the REAL router with an operator cert across every operator-read
  route (asserting none 404 — i.e. all are mounted) and an agent cert on `/events` (asserting 403).
  This guards the whole class: a future route registered on the inner mux but not served fails.

This corrects the `control-plane` capability. No logic change to the search itself.

## Impact

- Affected specs: `control-plane`
- Affected code: `internal/controlplane/enroll_http.go` (mount), `operator_routes_test.go` (new test).
- Not in scope: changing the search behavior (correct); consolidating the inner/served mux into one
  registration (a refactor — the guard test makes the duplication safe for now).
