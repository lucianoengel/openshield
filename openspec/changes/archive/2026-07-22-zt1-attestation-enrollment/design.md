## Context

`AttestationVerifier.Enroll(subject, akPub *ecdsa.PublicKey, golden map[int][]byte)` is the programmatic
enrollment point. Distribution needs to (a) capture those three values from a device, (b) serialize them
to a file an operator can move to the gateway, and (c) load and enroll them. `attest` already has the
serialization primitives: `AK.PublicKeyBytes()` marshals the AK public area and `ParseAKPublicKey` parses
it back to the `*ecdsa.PublicKey` the verifier needs.

## Goals / Non-Goals

**Goals**
- An `AttestationEnrollment` record (subject, AK public bytes, golden PCR values) with a JSON file format.
- `posture.BuildEnrollment(tpm, ak, subject, pcrs)` — capture a device's record.
- `gateway.LoadAttestationEnrollments(verifier, path)` — load and enroll, fail closed on bad records.
- Gateway-binary wiring (load before serving).

**Non-Goals**
- Automated network enrollment with live credential activation over the wire — the larger follow-up.
- The endpoint re-attestation loop — deployment wiring.
- Baseline rotation / multi-baseline per device — a single golden baseline per record here.

## Decisions

### D1 — File-based distribution, consistent with the posture roster
The gateway already loads a posture roster from an operator-distributed file (`LoadPostureRoster`).
Enrollment follows the same model: the operator captures a known-good device's record and distributes a
file; the gateway loads it at startup. This keeps the trust decision explicit and operator-owned (which
devices are trusted, and their known-good state) and matches an existing, understood pattern rather than
inventing a new distribution mechanism.

### D2 — JSON with the AK public bytes and hex PCR values
The record is JSON: `subject` (string), `ak_public` (base64 of `AK.PublicKeyBytes()`), and `pcrs` (a map
of PCR index → hex value). The file is `{"enrollments": [ ... ]}`. base64/hex keep it a readable,
diff-able, operator-editable text file. The loader parses `ak_public` with `attest.ParseAKPublicKey` (the
exact inverse of capture) so a loaded enrollment is byte-identical to a programmatic one.

### D3 — Fail closed on a bad record, never a silent skip
A record with an empty subject, unparseable AK bytes, or an empty PCR baseline is an **error** that fails
the whole load — not a skipped entry. A silently-skipped device would be treated as unenrolled and denied
(fail closed on the access side), but the operator would believe it was loaded; surfacing the error at
load time is the honest behavior. This mirrors `LoadPostureRoster`, which errors on a malformed line.

### D4 — Capture trusts the device; the record carries a genuine-TPM AK
`BuildEnrollment` captures the AK public and reads the golden PCRs from the device's TPM. The AK it
captures is one proven genuine-TPM-resident by credential activation (D184) at enrollment time; the
file-based flow trusts the operator's capture of that proven AK (D1). The honest limit — that
file-distribution does not re-prove genuineness at load — is stated in the proposal, and the automated
network enrollment that does re-prove it is the named follow-up.

## Risks / Trade-offs

- **File distribution trusts the operator's capture** — inherent to the roster model; stated (D1/D4). The
  automated network enrollment closes it and is the follow-up.
- **A single golden baseline per device is brittle across firmware updates** — accepted here (as in the
  PCR policy increment); a legitimate update re-captures the record.

## Migration Plan

Additive: a record type + (de)serialization, one endpoint helper, one gateway loader, one binary wiring
block. No proto or verifier change.

## Open Questions

- Whether enrollment records should eventually come straight from the control-plane enrollment records
  rather than a distributed file. Deferred to the automated-enrollment follow-up.
