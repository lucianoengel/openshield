# Verify signed telemetry on ingest (T-017 over the wire)

## Why

The control plane persists telemetry tagged with a SELF-ASSERTED agent id (D41): anyone who can
publish to NATS can claim to be any agent, and nothing checks. Per-agent identity exists (D44) —
agents have keypairs, enrollment binds them, `VerifySigned` checks a signature and a monotonic
sequence — but that verification is never applied to the telemetry stream. So the evidentiary
property is unrealised: the fleet view is unattributable and suppression is undetectable. This
wires identity to ingest: agents SIGN their telemetry, and the control plane VERIFIES it before
persisting, attributing it to the proven agent and detecting gaps.

## What changes

**A signed telemetry envelope.** A `SignedTelemetry` message wraps a marshalled telemetry payload
(Event / ClassificationSummary / Decision) with the agent id, a monotonic sequence, and a
signature over `canonical(agent_id, sequence, payload)` — the exact bytes `VerifySigned` checks.
Agents publish the envelope to a signed subject.

**The agent signs its telemetry.** A `SignedPublisher` holds the agent's identity (D44) and a
monotonic counter, signing and publishing each telemetry message. One counter per agent across all
kinds, so the control plane's sequence check sees the whole stream and a dropped message leaves a
detectable hole.

**The control plane verifies before persisting.** It subscribes to the signed subject, calls
`VerifySigned` (signature against the ENROLLED key, sequence for gaps/replays), and only on success
unmarshals the payload and persists it — attributed to the VERIFIED agent id, not a self-asserted
one. A bad signature, an unknown or revoked agent, or a replay is REJECTED and counted; a sequence
gap is recorded (suppression) while the authentic message is still stored. Rejections and gaps are
observable, never silent.

**The unsigned path stays for compatibility, clearly labelled.** The existing unsigned subjects
remain (a single-node dev agent that has not enrolled), but telemetry that arrives signed and
verified is marked as such, so the aggregate distinguishes attributable-and-verified from
self-asserted. Production enrolls and signs; the unsigned path is a dev convenience, stated.

## What this does NOT claim or cover

- **It does not authenticate the CONNECTION (mTLS).** This authenticates the MESSAGE — who signed
  it, in what order — which is the evidentiary property. Transport-layer auth is complementary and
  a TLS-config concern (as T-017 stated), not this.
- **Root on the agent host still forges** (D16): it can read the identity key and sign anything the
  agent could. The guarantee is attributable-and-revocable telemetry with detectable suppression,
  not unforgeable-against-host-root.
- **It does not verify the unsigned legacy path.** Unsigned telemetry stays self-asserted (D41);
  it is retained for a not-yet-enrolled dev agent and labelled, not silently trusted as verified.
- **It does not add the enrollment network endpoint.** Enrolling an agent over the wire is the
  sibling change; this assumes the agent is enrolled and focuses on the signed telemetry path.

## Decisions

Depends on **D44** (per-agent identity, `VerifySigned`), **D41** (the self-asserted aggregate this
upgrades), **D24** (the NATS boundary), and **D10** (only the summary crosses — the signed payload
is still a boundary-safe type).

Establishes a new decision: **telemetry is verified on ingest against the enrolled agent key — a
bad signature, unknown/revoked agent, or replay is rejected and counted, a sequence gap is recorded
— so the fleet view becomes attributable and suppression detectable; the unsigned legacy path
remains for a not-yet-enrolled dev agent, labelled self-asserted, never silently trusted as
verified.**
