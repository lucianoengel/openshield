# Wire view accountability into the write-capable control plane (T-013 seam)

## Why

D20 requires an audit trail of who VIEWED an investigation, not only who acted. T-013 built the
mechanism on the write-capable ledger but deferred wiring it, because the query CLI is a
signer-less verifier that must hold no signer (D30) — a read surface cannot append. The
write-capable service that serves fleet queries is the control plane (D41/T-023), and that is where
view accountability belongs. This wires it there.

## What changes

**The control plane records a view when an investigation is served through it.** `Server.View(...)`
serves the telemetry for an investigation AND records that it was viewed — viewer, what was
queried, when — into an `investigation_views` table. A query that returns evidence and a record
that the query happened are one operation, so viewing cannot be separated from being logged.

**The viewer is recorded and labelled unauthenticated.** There is still no authenticated OPERATOR
identity — agent identity (T-017/D44) authenticates AGENTS, not the humans querying. So the recorded
viewer is the caller-supplied identity (in practice the OS user), labelled `unauthenticated:` so it
is never mistaken for a verified operator. This is the same honest posture T-013 took, now on the
service that can actually record it.

**The view log is readable.** `Server.Views(...)` returns the recorded views, so "who looked at
this subject" is answerable — the accountability D20 requires.

## What this does NOT claim or cover

- **The view log is not the evidentiary ledger, and the viewer is not authenticated.** Like the
  fleet aggregate (D41), the view log has no hash chain or forward-secure signatures; a compromised
  control plane could alter or omit a view record. And the viewer is self-asserted (OS user) until
  an authenticated operator identity exists — a separate gap from agent identity. Both are stated;
  overclaiming viewer accountability as tamper-proof would be exactly the failure the project
  forbids.
- **It does not authenticate the operator.** Operator identity/authn is a distinct, unbuilt piece
  (the sibling of T-017 for humans). The view record captures the OS-level identity available, no
  more.
- **It does not expose a network query API.** `View`/`Views` are Server methods, the same shape as
  the existing Telemetry read-backs; a network-exposed investigation API is a later interface
  decision. This closes the "views are recorded when served" seam at the method level.
- **It does not record CLI-local reads of the agent's own ledger.** Those go through the signer-less
  CLI against the local ledger, which still cannot append (D30). Investigation VIEWING through the
  fleet service is what is accountable here; a single-node local read is the operator reading their
  own machine.

## Decisions

Depends on **D20** (who viewed an investigation), **D41/T-023** (the write-capable control plane),
**D30** (why the CLI cannot record it), and **T-013** (the deferred seam and its honest framing).

Establishes a small new decision: **view accountability is recorded by the write-capable control
plane when an investigation is served — viewer + query + time — with the viewer labelled
unauthenticated until operator identity exists, and the view log carrying the same non-evidentiary
caveat as the fleet aggregate.**
