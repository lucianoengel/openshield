## Context

The agent↔control-plane boundary has two channels: the enrollment HTTP endpoint
(`internal/controlplane/enroll_http.go`, `ServeHTTP`) and the NATS telemetry
connection (`internal/transport/nats`, `Connect` — which already accepts
`nats.Option`, and the control plane's own `nats.Connect` subscribe side). Both
are plaintext. Ed25519 signing (D50) sits ABOVE them and is unaffected by this
change; the goal is to secure the channel beneath the signature.

## Goals / Non-Goals

**Goals:**
- Mutual TLS on both agent-facing channels: server authenticates the agent's
  client cert and the agent authenticates the server's cert, against a shared CA.
- Confidentiality: telemetry and the enrollment token are no longer readable on
  the wire.
- Fail-closed: with TLS enabled, a plaintext or wrong-CA peer is REFUSED, never
  downgraded.
- Opt-in and honest: OFF by default (dev loop stays plaintext); enabling requires
  explicit cert/key/CA config.
- One TLS-config seam reused by all three call sites (enroll server, agent NATS,
  control-plane NATS).

**Non-Goals:**
- Replacing or weakening Ed25519 signing — mTLS is a second, independent layer.
- Certificate issuance / rotation / a PKI — certs are provided out of band
  (the fleet e2e uses a throwaway CA). Cert lifecycle is a later concern.
- Protecting keys from host root (D16): filesystem perms + the agent user are the
  bar, the same as the signer key. Documented, not overclaimed.
- Encrypting at rest, or TLS on any internal/loopback-only surface.

## Decisions

**One loader, two `*tls.Config`s.** A small package (`internal/transport/tlsconf`)
loads a CA bundle + a cert/key pair and produces a server config
(`ClientAuth: RequireAndVerifyClientCert`, `ClientCAs: pool`) and a client config
(`RootCAs: pool`, `Certificates: [pair]`). Both set `MinVersion: tls.VersionTLS13`.
The same loader feeds the enroll HTTP server, the agent's NATS `nats.Secure`
option, and the control plane's NATS connection.

**Opt-in via config, fail-closed when on.** Enablement is presence of the cert
paths (env `OPENSHIELD_TLS_CA` / `OPENSHIELD_TLS_CERT` / `OPENSHIELD_TLS_KEY`).
When set, the enroll endpoint is served with `http.Server{TLSConfig}` +
`ServeTLS`, and NATS uses `nats.Secure(clientCfg)` + client cert. When unset,
behaviour is exactly as today (plaintext) — so the dev loop and existing tests
are unchanged. There is NO "try TLS then fall back to plaintext" path: a
misconfigured or hostile peer fails the handshake and is refused. That is the
whole point — a silent downgrade would reintroduce the gap.

**mTLS and signing are independent and BOTH enforced.** A peer that presents a
valid client cert but sends a badly-signed message is still rejected by
`VerifySigned` (D50); a validly-signed message over a failed handshake never
arrives. Neither layer is trusted to do the other's job. A test asserts a
cert-authenticated-but-bad-signature message is still rejected, so the layers are
provably not conflated.

**`RequireAndVerifyClientCert`, not `VerifyClientCertIfGiven`.** The server
demands a client cert — an agent with no cert is refused at the handshake, before
any token is seen. This is what closes the token-capture-and-replay path: a rogue
agent cannot even open the enrollment channel without a fleet-issued client cert.

## Risks / Trade-offs

- **Cert distribution is now a prerequisite.** mTLS moves trust to "who holds a
  CA-signed client cert." Issuance is out of scope here; the risk is that weak
  cert handling undoes the benefit. Documented as a follow-up (PKI/rotation), not
  silently assumed solved.
- **Host root still wins (D16).** A client key readable by host root is
  compromisable, the same bar as the signer key. mTLS raises the on-path bar; it
  does not defend a compromised host. Stated plainly in docs.
- **Config surface grows.** Three new env vars per process. Mitigated by the
  single loader and off-by-default: a misconfiguration fails loudly at startup
  (cert load error), never silently to plaintext.
- **Test/dev friction.** Kept out of the default path: unit tests and the local
  loop run plaintext; only the fleet e2e exercises the mTLS path, with a CA it
  generates and throws away.
