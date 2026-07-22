## Context

The verifier exposes `Challenge(subject) → nonce`, `VerifyReport(report)`, and `IsAttested(subject)`.
The transport must carry a nonce request from device to gateway (reply with the nonce) and a report from
device to gateway (fire-and-forget, verified on arrival). This mirrors the existing risk/posture NATS
subscribers, with one simplification: an attestation report authenticates itself.

## Goals / Non-Goals

**Goals**
- A request/reply challenge subject and a publish report subject.
- Gateway `AttestationResponder`: serve challenges from the verifier, verify reports into it.
- Endpoint `posture.Attest`: request → quote → publish.
- Gateway-binary wiring (start the responder when configured).
- End-to-end proof over embedded NATS + real swtpm.

**Non-Goals**
- Enrollment distribution (AK public + golden baseline per device) — a separate operational mechanism,
  deferred (noted).
- The endpoint re-attestation loop/cadence inside a running fleet-agent binary — deployment wiring.
- Any change to the verifier's crypto (unchanged from increment 4).

## Decisions

### D1 — The report needs no signature layer; the quote is self-authenticating
Posture and risk updates are signed (ed25519) because they are self-reported claims — the signature says
*who* said it. An attestation report is a TPM quote signed by the device's AK, and `VerifyReport` checks
it against the AK enrolled for that subject. A report published under a victim's subject but signed by an
attacker's AK fails verification; a report with a stale nonce fails the freshness gate. So the transport
carries the raw report — no outer signature — and forgery is caught by the existing verification, not by
a second crypto layer. This is a genuine simplification, not a gap.

### D2 — Challenge is request/reply; report is publish
`Challenge` is a synchronous need (the device must have the nonce before it can quote), so it uses NATS
request/reply: the device sends its subject, the responder replies with the nonce bytes. The report is
asynchronous and verified on arrival, so it is a plain publish the responder subscribes to — matching the
posture/risk subscriber shape (drop-and-count on failure, observable not silent).

### D3 — Raw bytes on the wire for the challenge, the existing proto for the report
The challenge request payload is the subject string and the reply is the nonce — both opaque bytes, no
new proto needed. The report reuses the `AttestationReport` message from increment 4. Minimal surface.

### D4 — Honest note on the challenge-reset race
A one-shot nonce means a challenge request overwrites any pending nonce for that subject. An attacker who
can publish to the challenge subject could reset a victim's in-flight nonce (a narrow freshness DoS, not a
forgery — they still cannot produce a valid quote). In deployment the NATS channel is mutually
authenticated (mTLS, D55), so only enrolled agents reach it, and re-attestation is cheap and automatic.
Recorded, not hidden.

## Risks / Trade-offs

- **Challenge-reset race** — bounded to a freshness DoS on an authenticated channel; noted (D4).
- **Verifier not yet enrolled from real records** — the responder assumes enrollment exists; enrollment
  distribution is the stated follow-up. Until then the responder simply rejects unenrolled subjects
  (fail closed).

## Migration Plan

Additive: two subject constants, one responder type, one endpoint client function, one binary wiring
block. No proto or verifier change. Existing behavior unaffected unless the responder is started.

## Open Questions

- Whether enrollment distribution should reuse the posture-roster file format or come from the
  control-plane enrollment records directly. Deferred with the enrollment follow-up.
