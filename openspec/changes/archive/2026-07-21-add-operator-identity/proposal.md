## Why

T-013 requires an audit of WHO viewed an investigation — the privacy trail records
not only who acted, but who looked. The mechanism exists (`RecordView`/`View`
write an `investigation_views` row and a chained ledger entry), but the viewer is
a caller-supplied string. The code says so plainly: callers pass
`"unauthenticated:<os-user>"` "until operator authentication exists." So the
accountability trail records a name nothing verifies — a viewer can type any
identity, and the audit cannot tell a real operator from a fabricated one.

mTLS (D55) just gave the control plane a way to authenticate a peer. That is
exactly what the view-audit is missing: an identity bound to something the
operator HOLDS, not something they ASSERT.

## What Changes

- The control plane exposes an investigation-view HTTP endpoint that REQUIRES a
  client certificate (mutual TLS, D55) and records the view under the identity
  taken from the VERIFIED TLS peer certificate — `operator:<CN>`, not a
  caller-supplied string.
- A request with no verified client certificate is REFUSED — no accountable
  identity, no view (the existing `ErrNoViewer`/D20 rule, now enforced by
  authentication rather than a non-empty check).
- Recorded identities stay distinguishable: authenticated views are
  `operator:<CN>`; the legacy library path keeps its explicit
  `unauthenticated:<os-user>` marking, so the trail shows which views are
  accountable and which are self-asserted.
- The view is recorded BEFORE the evidence is returned (unchanged invariant): an
  attempted view is worth recording even if the read fails.

## Capabilities

### New Capabilities
- `operator-identity`: authenticated operator identity for privileged read
  surfaces — the investigation-view endpoint binds the recorded viewer to a
  verified mutual-TLS client certificate instead of a self-asserted string.

### Modified Capabilities
<!-- privacy-features already requires the view-audit; this ADDS the
     authenticated-identity property rather than changing that requirement. -->

## Impact

- New code: an authenticated view HTTP handler that extracts the peer-cert CN
  from `r.TLS`, refuses without one, and calls the existing `View`. Served under
  the D55 server TLS config; when TLS is off, the endpoint is not exposed (there
  is no authenticated identity to record).
- Affected: `internal/controlplane` (view handler + identity extraction),
  `cmd/openshield-server` (route wiring under the existing TLS server), docs
  (new D-number).
- SCOPE (stated honestly): this is AUTHENTICATION, not AUTHORIZATION. Any
  CA-issued client cert authenticates as an operator; distinguishing an
  operator-role cert from an agent-role cert (separate CAs, or cert OU/roles) is
  a documented follow-up. D14 (observe-only) and D16 (host root defeats the key)
  hold.
