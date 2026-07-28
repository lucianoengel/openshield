# A decision crossing the trust boundary is never checked against its contract

## Why

`core.ValidateDecision` checks the things that matter about a Decision: the action is not
`UNSPECIFIED`, the action is one the closed set actually contains, confidence is present and within
`[0,1]`, and a policy id and version identify what produced it. Its own comment states the stakes:

> An unknown action is a signal that the producer and consumer disagree about the contract, which is
> a security event, not a reason to permit the operation.

**It has no caller.** Decisions arriving as fleet telemetry are unmarshalled, keyed by event id,
inserted into `fleet_telemetry`, and projected into `unified_alerts` — the stream that feeds
correlation, incidents and entity risk — without ever being checked.

## What that permits

The signature IS verified first (D44), so this is not open injection. It is what an **enrolled agent**
can do: one that is compromised, one whose key leaked, or one running a version that disagrees about
the enum.

- **Forged severity.** `severityForDecision` calls `Severity(confidence)`, which returns CRITICAL for
  anything at or above its floor. Confidence is never range-checked on ingest, so a decision carrying
  `confidence: 999` becomes a CRITICAL alert. An agent can manufacture critical alerts at will — and
  the engine's own producer clamps confidence strictly below 1.0 (D4), so nothing in-process would
  ever emit such a value. The clamp is on the producing side only.
- **An action outside the closed set.** `alertableAction` admits anything that is not `UNSPECIFIED`
  and not `ALLOW`, so an unknown action number is projected. `enforcementAction` is a switch over the
  known set and returns false for it, so the alert is graded as if nothing was enforced. The comment
  on that switch says a total mapping is "exactly what makes this mapping safe: a compromised control
  plane cannot invent an action whose severity we failed to consider" — true of the control plane, and
  the telemetry path was never held to it.
- **No provenance.** A decision with no policy id or version is stored and projected, and D344's
  replay has nothing to check it against.

## What Changes

- A decision is validated before it is projected. One that fails is **not** projected into the alert
  stream, is **counted**, and is **logged** naming what failed.
- It is still stored as telemetry. A malformed decision arriving is itself evidence, and destroying
  it to keep the alert stream clean would trade one silence for another.
- The counter is exposed on `/metrics`, which the D348 guard now enforces automatically.

## Impact

- Affected specs: `decision-contract`
- Affected code: `internal/controlplane`
- No proto change, no migration, no new dependency.
- No effect on well-formed decisions, which is every decision this platform's own agents produce.

## Honest limits

- **This does not make a verified agent trustworthy.** A compromised agent can still send *valid*
  decisions that are false — a BLOCK that never happened, an ALLOW for an event it invented. Contract
  validation bounds what it can EXPRESS, not whether it is telling the truth, exactly as the closed
  action set bounds a compromised control plane without making it honest.
- **It does not detect a version-skewed agent as such.** An unknown action is refused and counted; it
  is not diagnosed. An operator seeing the counter move has to look at which agent, which is what the
  log line is for.
