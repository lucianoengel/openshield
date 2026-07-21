## Context

The engine's enforce() dispatch + the file enforcers are built and unit-tested
(TestQuarantineMovesFile). The gap was purely that no binary populated engine.Enforcers, so
the running product could never contain — the honesty gap the audit named.

## Goals / Non-Goals

**Goals:** register the file enforcers in the engine binary, opt-in, observe-only default.

**Non-Goals:** USB enforcer wiring; inline prevention (Phase B); an enforcement-policy config
surface.

## Decisions

**Opt-in behind OPENSHIELD_ENFORCE, mirroring the gateway.** The gateway registers its flow
enforcer only under OPENSHIELD_ENFORCE; the engine now does the same for the file enforcers.
Observe-only stays the default (D1) — without the flag the engine decides and records but
touches nothing.

**Quarantine always, encrypt on a key.** QUARANTINE_LOCAL needs only a directory, so it is
always registered when enforcing. ENCRYPT_LOCAL needs key custody (D57/D59), so it is
registered only when a symmetric key or an escrow recipient pubkey is configured.

**Extracted into a testable function.** The registration is `registerEnforcers(eng, log)`, so
the exact wiring is unit-tested (the file is really quarantined; observe-only really touches
nothing) and mutation-tested — the HON-3 bug (never register) fails a test.

## Risks / Trade-offs

- **Enforcement is destructive** (a file is moved/encrypted). Opt-in + observe-only default +
  audited outcomes are the guardrails; a wrong QUARANTINE moves a legitimate file, so an
  operator enables it deliberately.
- **Post-decision, not inline.** The file was already opened; this contains after the fact.
  Inline prevention is Phase B (the prefilter/watchdog), external-gated for the syscall.
