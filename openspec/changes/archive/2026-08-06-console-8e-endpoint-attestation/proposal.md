# CONSOLE-8e · The endpoint's hardware attestation

## Why

`OPENSHIELD_ATTEST_PCRS` appeared nowhere outside `cmd/openshield-fleet-agent`, so no real endpoint ever
attested.

Attestation is the **one device signal that is not self-reported** — the gateway sets `Attested` from its
own verification of a TPM quote, never from anything the device claims. That makes it the signal most
worth requiring, and its absence the worst to have: the verifier fails closed by design (D85/D186), so an
empty verifier means a deployment that turned attestation on **refused everything**.

That is the same failure D314 already recorded for a different cause. It came back because the fix wired
the simulator.

## What Changes

- The agent-side orchestration moves from a `main` package into `internal/posture`, which already owned
  the enrollment handshake, the quote and the loop.
- `openshield-engine` attests, off its main path.
- The simulator runs the same shared path and sheds 112 net lines.
- `ParsePCRs` moves with its test.

## Impact

- Affected specs: `device-attestation`.
- No proto change, no migration. Off unless PCRs are configured.

## The extraction is the point

Duplicating ~120 lines of TPM orchestration into a second binary is how two agents come to disagree about
what "attested" means. The pre-existing real-TPM scenario for the simulator now exercises the same code
the engine runs, so the move has a regression test on both sides rather than one.
