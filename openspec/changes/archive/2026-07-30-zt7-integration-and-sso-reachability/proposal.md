# Operator SSO shipped unusable, and an integration test is what found it

## Why

D372 and D373 were covered by package tests: an `httptest` handler driven with a synthesised TLS state.
Those prove the gate's logic. They cannot prove the wiring — that the shipped binary reads the same table,
that `openshield-server operator-role set` writes what the running server reads, or that a change reaches a
connection already open.

Writing that integration test found **operator SSO could not be used in any deployment**. The control
plane's HTTP surface is mutual TLS with `RequireAndVerifyClientCert`, so a client with no certificate — which
is exactly what an SSO operator is — is refused at the handshake with `tls: certificate required`, before
the bearer token is ever read.

This is the unwired-feature shape this project keeps finding, in a feature shipped one commit earlier.

## What changes

- `Config.ServerConfigOptionalClientCert` — `VerifyClientCertIfGiven`. A presented certificate is still
  verified against the CA; only ABSENCE stops being fatal at the handshake, becoming a 401 one layer up.
  Used **only** when operator SSO is configured, so a deployment without an identity provider is unchanged.
- `OPENSHIELD_OPERATOR_OIDC_KEYS_DIR` — static issuer keys as an alternative to a JWKS URL, mirroring the
  gateway's existing surface. Exactly one of the two may be set; two key sources is ambiguous about which is
  authoritative, and a deployment that rotated the ignored one has a silent trust problem.
- `NewOperatorVerifier` / `NewOperatorVerifierWithSource` — separate constructors rather than relaxing the
  ZTNA ones, so a ZTNA gateway missing its role-claim setting still fails at construction instead of per
  request.
- Two integration cases against the real binary, real mutual TLS and the real CLI.

## Impact

- Behaviour change confined to deployments with operator SSO configured.
- No new dependency, no proto change, no migration.
- Affected capability: **operator-identity**.

## The assertion that was vacuous, and the mutation that proved it

The safety property here is that "optional" must not become "unverified". The first version of that
assertion built a second PKI and used its client:

```go
forged := other.operator(t, "admin", "mallory")
if _, err := forged.Get(base + "/alerts"); err == nil { t.Fatal(...) }
```

It passed — and it passed against a mutant that removed server-side verification entirely
(`RequestClientCert`). The reason is that the forged client did not trust the SERVER's CA either, so the
handshake failed **client-side** and the assertion was satisfied without the server having rejected
anything.

`foreignCertClient` fixes the direction: trust this server's CA as a root, present a certificate from a
different one, so the only thing that can fail is the server refusing the client. The same mutation now
fails the test.

Worth recording because the vacuous version looked stronger than it was — it built a whole second PKI,
which reads as thorough.

## Honest limits

- The relaxation is at the listener, so with SSO enabled an anonymous TCP client can complete a handshake
  and receive a 401 where previously it was refused at the TLS layer. That is a slightly larger
  unauthenticated surface, accepted because it is the only way a bearer token can be presented at all, and
  bounded by every route requiring a role.
- SCIM, JIT provisioning and DPoP on the operator path remain absent, unchanged from D373.
