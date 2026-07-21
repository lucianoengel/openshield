# Add per-agent identity and enrollment (T-017)

## Why

The control plane accepts telemetry from anyone who can connect, tagged with a SELF-ASSERTED
agent id (D41). That is a placeholder, and review flagged the alternative — a shared fleet secret
— as a fleet-wide risk: one compromised agent would equal fleet compromise. Telemetry is
evidentiary (it feeds the fleet view and the dead-man's-switch), so it needs the same integrity
bar as the audit log: individually attributable, tamper-evident, and revocable per agent. This
builds that.

## What changes

**Each agent has its own Ed25519 identity keypair — never a shared secret.** The agent generates
its keypair locally; the private key never leaves the host. Compromising one agent yields one
agent's key, not the fleet's.

**Enrollment binds an agent's public key to an identity via a single-use, short-TTL token.** An
admin issues a token (stored as a hash, with an expiry); the agent presents the token plus its
public key and chosen agent id; the control plane verifies the token is valid, unexpired and
unused, records the identity, and burns the token. A token is enrollment-only — it is not a
signing key, so a stolen token lets an attacker enroll a bogus agent (revocable, and the admin
sees an unexpected enrollment) but never impersonate an existing one.

**Telemetry is individually signed with a monotonic sequence, and the control plane verifies
it.** The agent signs each telemetry envelope `{agent_id, sequence, payload}` with its identity
key. The control plane verifies the signature against the enrolled public key and checks the
sequence: a gap means messages were SUPPRESSED between the agent and the control plane — the
evidentiary property the audit log's sequence numbers also provide (an audit trail that cannot
reveal suppression is not evidentiary). A gap is recorded, not silently accepted.

**Identity is revocable.** The control plane can revoke an agent; a revoked agent's telemetry is
rejected. Revocation is per-agent, so containing a compromised endpoint does not disturb the
fleet.

## What this does NOT claim or cover

- **It is not mTLS transport authentication.** This is application-layer identity: signed messages
  verified against enrolled keys. mTLS (authenticating the CONNECTION) is a TLS-config concern for
  the deployment and is complementary, not built here — stated so the layering is clear. The
  evidentiary property (who signed this, in what order) is what this delivers.
- **It does not make the agent unimpeachable on a compromised host.** Root on the endpoint can read
  the agent's private key and sign anything the agent could (D16). The narrow, honest guarantee:
  telemetry is attributable to a key, that key is revocable, one compromised agent is not the
  fleet, and suppression between agent and control plane is detectable. Root-on-host is defeat, as
  always.
- **It does not solve key rotation or re-enrollment.** An agent keeps its enrolled key for its
  lifetime here; rotation is a later refinement, noted.
- **The enrollment admin is trusted.** Whoever issues tokens can enroll agents. Token issuance
  authorisation is the control plane's operator concern; TOFU-with-admin-approval is the
  alternative enrollment mode noted for deployments that prefer it.

## Decisions

Depends on **D41/T-023** (the control plane that enrolls and verifies), the review finding A6
(per-agent revocable identity; single-use short-TTL token or TOFU; NEVER a shared fleet secret),
and the audit log's sequence-number reasoning (suppression must be detectable).

Establishes a new decision: **each agent has its own Ed25519 identity (never a shared secret),
enrolled via a single-use short-TTL token, signing telemetry with a monotonic sequence the control
plane verifies for gaps; identity is revocable per agent; root-on-host defeats it and mTLS is a
complementary transport-layer concern, not this.**
