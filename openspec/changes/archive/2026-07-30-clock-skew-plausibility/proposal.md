# A compromised endpoint controls its own clock, and one detector believed it

## Why

Clock skew was the third of four properties the enterprise gap assessment named as unproven. Checking it
produced three findings, and the third reshaped the change.

**1. Liveness was already immune.** The dead-man's-switch derives from `received_at`, the control plane's
own clock (SEC-3). An agent cannot make itself look alive, or dead, by lying about the time.

**2. Beaconing trusts the endpoint's clock, and has to.** It measures the rhythm of outbound contacts using
`observed_at`, for a reason recorded where it is used: receipt time would measure the transport, not the
endpoint. Correct — and it means an implant authors the evidence the detector consults.

**3. That evasion cannot be closed here, and the first version of this change tried.** The obvious fix —
distrust timestamps disagreeing with receipt beyond a tolerance — destroys beaconing outright, because this
product's own offline queue (D40/D67) makes past-dated telemetry entirely normal. Written and run, it took
detections from **1 to 0**.

So a timestamp in the past is indistinguishable from legitimate lateness. No threshold separates them,
because the difference is not in the data.

## What changes

Only the **future** direction is checked, which is unambiguous: an event cannot be observed after it was
received. Beyond a tolerance it is measured by receipt time, counted, and the agent is named once.

That is a narrower claim than the first version made, and it is one the data supports. It is also worth
having on its own — a future-dated event sorts to the top of a timeline and can sit outside an analysis
window entirely, so an endpoint dating its contacts forward can push them out of the sweep meant to catch
them.

## Impact

- `OPENSHIELD_CLOCK_SKEW_TOLERANCE`, default 2m. No new dependency, no proto change, no migration.
- Affected capability: **behavioral-detection**.

## Honest limits

- **Backward skew remains undetectable**, and therefore so does the beaconing evasion in its most likely
  form. Closing it needs a time source the endpoint does not control — D64's "completeness needs an external
  anchor", applied to time — which is a much larger piece of work. Stated in the code rather than implied.
- The tolerance is a plausibility bound, not a synchronisation requirement. An implant skewing by less than
  it still shapes its own rhythm.
- Only beaconing consults this. Other time-ordered analysis (incident timelines) still uses whatever it used
  before; extending it there was not in scope and is not claimed.

## What the tests had to be argued down to

The end-to-end assertion — "a future-dated beacon is still detected" — **cannot work**, and finding out why
mattered. Seeding flows inserts them in a tight loop, so their receipt times are milliseconds apart and the
fallback has no rhythm to find.

The first version of that test **passed anyway**, on rows a previous test had left in a shared table.
Clearing before seeding exposed it. So the decision is now tested where it is made, and the existing
beaconing cases are what prove the normal path still works — which is the honest split rather than an
end-to-end test that would have been theatre.
