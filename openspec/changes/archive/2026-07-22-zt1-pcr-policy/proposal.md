## Why

Increments 1 and 2 prove a quote is authentic (signed by an AK, fresh) and that the AK lives in a
genuine TPM. But the quote's payload — the attested PCR digest, the fingerprint of the machine's
measured-boot state — is still just returned, never judged. This increment makes it actionable: a
policy that compares the attested PCR state against a known-good ("golden") baseline, so a machine
whose boot measurements have drifted (a changed bootloader, kernel, or firmware) fails attestation.
That is the point of measured boot — turning "the TPM says these are the measurements" into "these are
the measurements we expect."

## What Changes

- Read current PCR values from a TPM (to capture a golden baseline from a known-good machine).
- Compute the expected aggregate PCR digest the same way the TPM does (the hash over the selected PCR
  values in index order), so a server can compare it to a quote's attested digest without a TPM.
- A `PCRPolicy` built from golden per-PCR values that evaluates a verified quote: **compliant** when the
  attested digest equals the golden aggregate, **rejected** (typed error) on any drift.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `device-attestation`: adds a measured-boot PCR policy — evaluating a verified quote's attested PCR
  digest against a golden expected-PCR baseline.

## Impact

- **Code:** extends `internal/attest` (PCR read, expected-digest computation, `PCRPolicy`). Tested
  against real `swtpm`: golden state matches; extending a PCR (simulating boot-state drift) makes the
  same policy reject the new quote.
- **No proto/core change** — posture wiring is increment 4.
- **Scope note (honest):** this increment gates on the **golden aggregate digest**. Parsing the
  measured-boot **event log** (`binary_bios_measurements`) to attribute *which* measurement changed is
  a diagnostic enhancement, deliberately deferred: go-tpm ships no TCG event-log parser, `go-tpm-tools`'
  parser is barred by the D183 dependency decision, and hand-rolling the TCG binary format is a
  separate substantial effort that does not change the allow/deny outcome. The digest comparison is the
  gating mechanism; event-log attribution only explains a failure.
- **Scope:** increment 3 of 4 for ZT-1 (core → EK activation → **PCR policy** → posture wiring).
