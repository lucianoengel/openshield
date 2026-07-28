## Why

Two of the 170 declared settings are read by nothing, anywhere in the module. Both were found by asking a
question the existing guard deliberately does not ask, and each fails differently:

- **`OPENSHIELD_NOTIFY_DEDUPE_RETENTION` is never read, and the AUDIT TRAIL claims it was.** The prune
  itself runs — it is wired into the retention loop — but with a cutoff hardcoded to 24 hours, and it
  then records a compliance event whose policy string is the literal
  `OPENSHIELD_NOTIFY_DEDUPE_RETENTION=24h`. So an operator who sets that variable to 7d gets: their value
  ignored, the behaviour unchanged, and a retention record NAMING THEIR SETTING and asserting a value
  they did not choose. A compliance record that cites a knob nobody read is worse than one that omits
  it, because it is evidence of a policy that was never applied.
- **`OPENSHIELD_POSTURE_PUBKEY`** is dead. SEC-12 replaced the single fleet-wide posture key with a
  per-agent roster precisely because one shared key let any agent forge any other's posture, and the
  gateway stopped reading it. The declaration outlived its reader, so the configuration surface still
  offers it — and an operator who sets it believes posture is verified when the roster is what decides.

The `config` package's own doc says a hand-written schema fails when "the form offers a field the binary
never reads, an operator sets it, nothing happens, and nobody finds out until an incident", and that
deriving the schema makes that "structurally impossible". Derivation prevents a field the code never
had. It does not prevent a field whose READER WAS DELETED, which is what happened twice.

## What Changes

- **The prune reads the setting.** The cutoff comes from `OPENSHIELD_NOTIFY_DEDUPE_RETENTION`, and the
  recorded policy string is built from the value actually used — so the compliance record describes what
  happened rather than what a literal said.
- **`OPENSHIELD_POSTURE_PUBKEY` is removed** from the declared surface. Nothing reads it; offering it is
  worse than not having it, because it reads as configuration that does something.
- **A guard closes the class**, not just these two: every declared setting must be read somewhere in the
  module, with comments stripped so a mention in prose does not count as a reader. That is a question the
  existing per-command check cannot answer and explicitly declines — a binary's surface includes what its
  libraries read, so a command-scoped reverse check false-positives. Module-scoped, the question narrows
  to "does anything read this at all", which is exactly the dead-setting question and is provable.

## Capabilities

### Modified Capabilities

- `typed-config`: a declared setting must have a reader, and the retention of durable dedupe ids becomes
  a stated bound rather than an unused knob.

## Impact

- `cmd/openshield-server` — one loop.
- `internal/config` — one declaration removed, one guard added.
- No proto change, no migration. The prune's cutoff becomes operator-controlled, which is what the
  setting has always claimed to be.
- **Risk:** an operator can now set a retention SHORTER than the dedupe window, which would let a
  duplicate page. The default stays at 24h — far above the 10-minute window — and the value is validated
  as a duration, but a deliberately tiny one is the operator's to choose; the alternative is ignoring
  their configuration, which is the defect being fixed.
