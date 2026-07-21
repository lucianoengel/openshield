## Why

Agents authenticate their telemetry with Ed25519 (D50): every signed message is
attributable and integrity-protected, and the control plane rejects anything it
cannot verify. But that is a MESSAGE-level guarantee over a plaintext CHANNEL.
Today the enrollment token crosses plain HTTP and signed telemetry crosses plain
NATS, so an on-path attacker can:

- read all fleet telemetry (no confidentiality — the signature protects integrity,
  not secrecy), and
- capture an enrollment token in flight and enroll a rogue agent before the
  legitimate one does.

Signing was never meant to secure the channel; it secures the payload. The
transport itself has no authentication and no confidentiality. That is the gap.

## What Changes

- The agent-facing channels — the enrollment HTTP endpoint and the NATS telemetry
  connection — gain TLS with MUTUAL authentication: the agent verifies the
  server's certificate against a configured CA, and the server verifies the
  agent's client certificate against the same CA. Both ends are authenticated and
  the channel is confidential.
- This is DEFENCE IN DEPTH, not a replacement: Ed25519 signing stays exactly as
  is. mTLS authenticates the CHANNEL and the transport peer; the signature still
  proves per-message attribution and the forward-secure ledger (D30/D38) remains
  the evidence. A verified TLS peer whose messages fail signature check is still
  rejected (D50) — the two layers are independent.
- It degrades HONESTLY: TLS is opt-in via configuration (CA + cert/key paths),
  OFF by default for the local dev loop. When enabled, a plaintext or
  wrong-CA peer is REFUSED — never silently downgraded to plaintext.
- The podman fleet e2e gains a small throwaway CA and asserts: enrollment and
  telemetry succeed over mTLS, and a client without a valid cert is refused.

## Capabilities

### New Capabilities
- `transport-security`: TLS with mutual authentication for the agent-facing
  enrollment and telemetry channels — opt-in, fail-closed, layered under (not
  replacing) Ed25519 message signing.

### Modified Capabilities
<!-- No existing requirement changes: signing, verification and the observe-only
     boundary are unchanged; this adds a channel-security layer beneath them. -->

## Impact

- New code: a small TLS-config loader (CA + cert/key → `*tls.Config` for server
  and client), wired into the enrollment HTTP server and both NATS connections
  (control plane subscribe, agent publish). Env: cert/key/CA paths.
- Affected: `internal/controlplane` (enroll HTTP server + NATS subscribe),
  `internal/transport/nats` (`Connect` TLS option — already accepts
  `nats.Option`), `cmd/openshield-server`, `cmd/openshield-fleet-agent`,
  `deploy/fleet-e2e.sh` (CA + certs), docs (new D-number).
- No behaviour change unless TLS is explicitly configured. D14 (server still only
  observes) and D16 (host root defeats at-rest key protection — documented, not
  overclaimed) are respected.
