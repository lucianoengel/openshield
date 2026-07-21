## Context

`VerifySigned(agentID, seq, payload, sig, now)` exists (D44): verifies the signature against the
enrolled key and checks the sequence (in-order → advance; gap → accept+report; replay → reject).
The control plane's `handle` currently decodes unsigned telemetry and persists with a self-asserted
agent_id. `identity.CanonicalEnvelope(agentID, seq, payload)` is the signed byte string.

## Goals / Non-Goals

**Goals:**
- A signed telemetry envelope; agents sign and publish; the control plane verifies before persisting.
- Verified telemetry attributed to the proven agent; rejections/gaps observable.
- The unsigned path retained but labelled self-asserted.

**Non-Goals:**
- mTLS; the enrollment endpoint (sibling change); verifying the legacy unsigned path.

## Decisions

### SignedTelemetry proto + subject
```proto
message SignedTelemetry {
  string agent_id = 1; uint64 sequence = 2; string kind = 3;  // event|classification|decision
  bytes payload = 4;   // marshalled Event/ClassificationSummary/Decision
  bytes signature = 5; // over canonical(agent_id, sequence, payload)
}
```
Subject `openshield.v1.signed`. The payload is the same boundary-safe type as the unsigned path
(D10) — signing wraps it, it does not add content.

### Agent-side SignedPublisher
`transport/nats` (or a small signer) gains a `SignedPublisher{ identity, conn, seq }` with
`PublishEvent/Classification/Decision` that marshal the payload, increment ONE monotonic counter,
sign `canonical(agentID, seq, payload)`, and publish a `SignedTelemetry`. One counter across kinds
so the control plane sees the whole stream — a dropped message of any kind leaves a hole.

### Control-plane verify-on-ingest
Subscribe to `SubjectSigned`. Handler: decode `SignedTelemetry`, `VerifySigned(agentID, seq,
payload, sig)`:
- error (bad sig / unknown / revoked / replay) → increment `RejectedTelemetry`, drop (counted,
  never silent);
- success → unmarshal payload by kind, persist attributed to the VERIFIED agent_id with a
  `verified=true` marker; a reported gap increments `Gaps`.
Persistence reuses `insert`; a `verified` column (migration 008) distinguishes verified rows from
legacy self-asserted ones.

### Legacy unsigned path labelled
The existing unsigned subjects stay; their rows get `verified=false`. So a query can tell verified
(attributable) from self-asserted. Docs state production signs; unsigned is a dev convenience.

## Risks / Trade-offs

- **One sequence counter across kinds** means kinds interleave in the stream; that is fine — the
  control plane checks monotonicity of the whole per-agent stream, which is what detects suppression.
- **A rejected message is dropped, not stored.** Correct — an unverifiable message is not evidence;
  it is counted so the rejection is observable. A replay is dropped (already stored once).
- **Root forges** (D16). Stated. Attributable-and-revocable, not unforgeable.
- **Two ingest paths** (signed + legacy). The legacy one is labelled self-asserted; a future change
  can retire it once all agents enrol. Stated, not hidden.
