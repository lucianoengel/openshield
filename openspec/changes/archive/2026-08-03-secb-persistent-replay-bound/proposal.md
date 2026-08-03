# SEC-B · The replay bound was in memory, and the threat model said otherwise

## Why

`openspec/specs/enforcement/spec.md` carries this requirement:

> ### Requirement: A replayed control is refused
>
> A consumer SHALL refuse a control whose sequence is at or below the highest it has applied.

`docs/threat-model.md` states how:

> a MONOTONIC SEQUENCE, **stored rather than held in memory so a control-plane restart does not
> reopen the window**

The code was `applied uint64`, a plain struct field on `FleetControlSubscriber`, with no persistence
and no call site that could supply any. Neither the engine nor the gateway passed a state file, and
there was no analogue of `OPENSHIELD_SEQ_FILE` — which exists on the publisher side precisely because
*"without it a restart replays sequence numbers"*.

So the sentence in the threat model was true of the publisher and **false of the consumer, and the
consumer is where a replay is refused**. Every restart reset the bound to zero, and every fleet
control an attacker had ever captured off the subject became live again, bounded only by its own TTL.

The sharpest instance is the one the channel's own header comment names: a captured
`ENFORCEMENT_DISABLE`, re-sent after an operator restored enforcement. It is the most attractive
forgery target in the system — one accepted message turns the product off across a fleet — except
that it needs no forgery. The signature, the version and the expiry are all genuinely valid; waiting
for a reboot was the entire attack.

**Every unit test passed throughout.** The refusal logic was correct the whole time. What was missing
was anywhere to keep the number it consults, which no test that constructs a subscriber in memory can
observe.

## What changes

1. **The bound is persisted, and by default.** `OPENSHIELD_FLEET_CONTROL_SEQ_FILE` has a real default
   path rather than being opt-in, because a missing telemetry sequence costs a counted gap while a
   missing replay bound costs a security property the threat model asserts — and a guarantee that has
   to be switched on is a guarantee most deployments do not have.

2. **It is written BEFORE the control is applied, and a control whose bound cannot be written is
   refused.** Applying first and persisting after leaves a window in which a crash restores a bound
   below a control that already ran — the replay this exists to refuse, reintroduced by the code meant
   to prevent it. Persisting first can instead lose a control to a crash, which leaves the host
   ENFORCING and the control plane free to re-issue. Everything on this channel fails toward enforcing.

3. **The bound is proven readable and writable at startup.** A corrupt bound refuses to start, because
   "start fresh at 0" is exactly the attacker's preferred outcome. An unwritable one is reported
   distinguishably, so the binaries can allow the one downgrade that is legitimate — a read-only or
   ephemeral root filesystem — while never allowing it for corruption.

4. **The bound may not share a file with the telemetry sequence.** Both are a `uint64` in the same
   format and one is an obvious place to put the other. Shared, the telemetry high-water reaches the
   thousands within seconds of boot and every legitimate control below it is refused as a replay: a
   host that can no longer be told to stop enforcing, failing in the direction that looks like nothing
   is wrong.

5. **The threat model is corrected**, including the residual: a deployment may keep the bound in
   memory, the agent says so at startup, and the window is then stated rather than implied.

## Impact

- **Behaviour:** a host that never receives a fleet control is unaffected. A host that does now
  refuses replays across restarts instead of accepting them.
- **No schema, no proto, no migration.**
- **Two defects were found by trying to prove this end to end**, both fixed alongside because the
  proof is impossible without them:
  - a ledger anchored but never written to could not be reopened, so a process that started, recorded
    nothing and restarted could never start again;
  - the gateway's degraded counters — including the kill switch's suppression count — were reported
    only in access mode, so a gateway in its ordinary proxy mode reported none of them.
- **Deliberately not in scope:** persisting the KILL SWITCH state itself (a restart restoring
  enforcement is the correct fail-toward-enforcing behaviour, not a gap); replay bounding for response
  intents, whose three verbs are all restrictive so a replay fails toward more enforcement — though
  their expiry being optional is worth a look on its own.
