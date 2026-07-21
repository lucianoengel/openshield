## Why

HON-3 (P0). The production engine registered ZERO enforcers (`Enforcers` empty; the binary
never populated it), so despite the quarantine/encrypt/USB enforcers + two-tier prefilter +
watchdog all being built and unit-tested, PRODUCTION IS OBSERVE-ONLY — nothing can contain
anything. This is the prerequisite that makes DLP containment (and Phase B inline prevention)
mean anything.

## What Changes

- `cmd/openshield-engine`: `registerEnforcers` wires the file enforcers into the engine when
  `OPENSHIELD_ENFORCE` is set (observe-only default preserved, mirroring the gateway's opt-in
  flow enforcer). Always the quarantine enforcer; ENCRYPT_LOCAL on top when a key
  (OPENSHIELD_ENCRYPT_KEY) or recipient pubkey (OPENSHIELD_ENCRYPT_PUBKEY, escrow D59) is set.

## Capabilities

### Modified Capabilities
- `endpoint-engine`: the engine binary can register file enforcers, opt-in.

## Impact

- `cmd/openshield-engine/main.go`; `docs/decisions.md` D117.
- Proven (binary package): with `OPENSHIELD_ENFORCE` a QUARANTINE_LOCAL decision on a
  CPF-flagged file MOVES it into the quarantine dir and audits an "enforced" outcome; WITHOUT
  the flag no enforcer is registered and the file is untouched (observe-only default, D1).
  Guards mutation-tested: **never-register (the HON-3 bug) fails the test**; register-without-
  the-flag (observe-only broken) fails it.
- NOT in scope (stated): wiring the USB enforcer (device-attach events are a separate producer
  path); inline prevention timing (Phase B — the prefilter/watchdog are the inline path, this
  is post-decision containment D16); a config-file surface for enforcement policy (PLAT-5).
  Containment is post-decision, not prevention.
