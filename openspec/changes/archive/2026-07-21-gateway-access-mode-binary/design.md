## Context

`cmd/openshield-gateway` runs the egress forward proxy (D73–D79). The access proxy
(D87/D88/D89) is a different role — client-cert TLS, a service catalog, identity
authorization — and is only exercised in tests. This makes it a runnable mode.

## Goals / Non-Goals

**Goals:** run the AccessProxy as a binary mode; fail-fast on misconfig; reuse the
worker pool + ledger.

**Non-Goals:** the risk-publish channel (A.5b); a bespoke systemd unit; OIDC; posture;
hot-reload.

## Decisions

**Egress OR access, not both, in one process.** A gateway is deployed as an egress
forward proxy or a ZT access proxy — different roles on different ports. The access
branch (`OPENSHIELD_ACCESS_MODE`) runs the AccessProxy and returns; the forward-proxy
path is the else. A deployment wanting both runs two instances. This keeps each process
one role, one attack surface, one config.

**Fail-fast and LOUD — a ZT gate never boots misconfigured/permissive.** Every access
input is required and validated at startup: a missing client CA (nothing to verify
clients against), a missing server cert, an unloadable policy, or an empty catalog each
ABORTS. The failure mode of a Zero-Trust gate must be "does not start", never "starts
and admits everyone" — the deployment equivalent of the D87 fail-closed decision.

**The operator writes a default-deny access policy; the binary loads it.** The access
policy is identity-aware and default-deny (D87), which only the operator can author for
their services/roles. The binary loads it from a file (`policy.New`) and fails if it is
missing or unparseable — it never falls back to the observe-first default policy, which
would authorize nothing correctly and (being default-allow) admit everyone.

**Client-cert-required TLS is the front door.** The access listener is
`RequireAndVerifyClientCert` with the client CA (D86): a connection without a
CA-issued client cert never completes the handshake — authentication happens before
the handler runs, and the handler resolves the verified identity (D86/D87).

## Risks / Trade-offs

- **Static catalog/policy (restart to change).** Onboarding a service or changing the
  policy is a config edit + restart today; SIGHUP hot-reload (like the CA rotation D79)
  is a noted follow-up.
- **The RiskStore is empty until A.5b.** Continuous verification (D89) works but has no
  risk feed yet, so it never fires until the publish channel lands — the mechanism is
  wired and inert, which is the honest state (a policy gating on absent risk allows,
  D89).
