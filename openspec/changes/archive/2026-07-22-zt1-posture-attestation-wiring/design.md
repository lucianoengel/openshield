## Context

The access proxy (D85–D90) already enriches a request's identity context with self-reported device
posture from a `PostureStore` and lets a default-deny policy require compliance. The `Attested` signal
must slot into that same `DevicePosture`, but with a fundamentally different trust origin: posture
booleans are the endpoint's word, whereas `Attested` must be the gateway's own conclusion from verifying
a TPM quote. This increment adds the verifier and the contract field, and wires the field from the
verifier — not from the wire.

## Goals / Non-Goals

**Goals**
- `core.DevicePosture.Attested`, exposed to policy.
- An `AttestationReport` proto (nonce + quote), carrying no self-asserted verdict.
- `gateway.AttestationVerifier`: enroll (AK pub + golden baseline), issue a one-shot nonce, verify a
  report (nonce + quote + PCR policy), expose per-subject attested state.
- Access proxy sets `Attested` from the verifier; a policy can require it.
- End-to-end proof with a real swtpm quote.

**Non-Goals**
- The NATS challenge/report transport (nonce beacon + report subject) — follow-up, stated.
- EK-cert validation at enrollment (increment 2's scope note) — the verifier consumes an already-enrolled
  AK.
- Changing the self-reported posture path (it stays as-is, honestly labeled).

## Decisions

### D1 — `Attested` is set by the gateway, never carried as a boolean on the wire
The `AttestationReport` proto carries the quote (`nonce`, `quote_attest`, `quote_sig_r`, `quote_sig_s`)
and the subject — the *evidence*, not a verdict. `DevicePosture.Attested` is computed by
`AttestationVerifier.VerifyReport` from that evidence. This is the whole point: a compromised endpoint
that could set `attested=true` in a message would defeat attestation, so the field simply does not exist
on the wire. It mirrors how the gateway derives risk/decision rather than trusting an endpoint's claim.

### D2 — One-shot server-issued nonce is the anti-replay boundary
`Challenge(subject)` mints a fresh random nonce (reusing `attest.NewNonce`), stores it per subject, and
`VerifyReport` requires the report's nonce to equal the stored one, then **consumes** it (a second report
under the same nonce fails). Without a server-controlled fresh nonce, a device that was once attested
could replay that quote forever after drifting. The nonce lifecycle lives in the verifier; the physical
delivery of the challenge is the deferred transport.

### D3 — Verification composes the three prior increments unchanged
`VerifyReport` is: nonce match (D2) → `attest.VerifyQuote(enrolledAK, nonce, quote)` (increment 1) →
`attest.PCRPolicy.Evaluate(verifiedQuote)` (increment 3). Enrollment stored the AK public (proven
genuine-TPM by increment 2's credential activation) and the golden baseline. No attestation crypto is
re-implemented here — this increment is pure composition + wiring.

### D4 — Enrollment binds subject → (AK public, golden baseline)
`Enroll(subject, akPub, golden)` registers a device. In production this is the output of increment-2
credential activation (the AK is proven genuine) plus a captured golden baseline; here the verifier takes
them as enrollment inputs. A subject with no enrollment can never be attested (its challenge/verify has
no key to check against) — unattested fails closed, consistent with D85.

### D5 — Access-proxy enrichment overlays server truth on self-report
In the access handler, after reading self-reported `DevicePosture` from the `PostureStore`, set
`dp.Attested = verifier.IsAttested(deviceSubject)` and `dp.HasPosture = true` when attested — so the
`Attested` a policy sees is always the gateway's verified conclusion, independent of (and unforgeable by)
the self-reported booleans. A policy requiring `attested` denies a device the gateway has not verified.

## Risks / Trade-offs

- **Verifier state is in-memory per gateway** — a gateway restart drops attested state until devices
  re-attest; acceptable (re-attestation is cheap and the deferred transport re-challenges), and it fails
  *closed* (unknown → unattested → denied).
- **Deferred transport means no live re-attestation cadence yet** — stated; the primitive is proven and
  the transport is a mechanical follow-up mirroring D89→D91.

## Migration Plan

Additive: one proto message (regenerated), one contract field (default false → existing policies
unaffected), one new verifier type, one access-proxy setter. No existing behavior changes unless a
policy opts into `attested`.

## Open Questions

- Whether re-attestation cadence (how often the gateway re-challenges) belongs with the transport
  follow-up or as a verifier TTL. Leaning TTL on the verifier; deferred with the transport.
