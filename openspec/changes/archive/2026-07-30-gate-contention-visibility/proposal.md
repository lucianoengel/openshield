# Under contention the gate discarded evidence and said nothing until shutdown

## Why

The last of the four properties the enterprise gap assessment named as unproven: per-node limits under
contention.

The file-open gate has three discard paths, and every one of them was logged **only on `ctx.Done()`**:

| Counter | What it means |
| --- | --- |
| `gateAuditDropped` | decisions were made that are **not in the ledger** — directly against D358 |
| `gateAsyncDropped` | gated opens were never fully classified, only their inline prefix seen |
| `suppress.Saturated()` | opens declined at the suppression ceiling |

Every one fires under contention, which is precisely when nobody is going to stop the process to find out.
A busy endpoint lost evidence silently for as long as it stayed up; a process that was SIGKILLed or crashed
never reported at all — so the load that caused the loss was also the reason the report never arrived.

The ingest listeners got continuous discard reporting in D348. The gate did not, and nothing noticed
because nothing had ever put the gate under load.

## What changes

- The gate's counters go through the existing `reportDiscards` — same mechanism, same rule: report only
  when a counter moves, so a healthy engine stays silent.
- `OPENSHIELD_GATE_ASYNC_QUEUE` makes the queue depth configurable. An overflow path that cannot be reached
  in a test is one written once and never exercised again.
- `OPENSHIELD_DISCARD_REPORT_INTERVAL` covers the listeners too, which had it hardcoded.

## Impact

- No behaviour change to decisions; a log line appears where there was silence. No new dependency, no proto
  change, no migration.
- Affected capability: **observability**.

## Honest limits

- **This makes the loss visible, it does not prevent it.** A queue with a bound will overflow under enough
  load, and the right response is an operator raising the bound or reducing what is gated — which they now
  have the information to do.
- **The engine still has no metrics endpoint.** This reports in the log, because giving every endpoint an
  HTTP port is a decision about the product's attack surface (D348's reasoning, unchanged). A deployment
  scraping metrics has to scrape the log.
- **Dropped audit rows are not recoverable.** The decision was made and its evidence is gone; the counter
  says how many, not which. Making them recoverable means a durable queue in front of the ledger, which is
  a different piece of work.
- Only the gate and the listeners are covered. Other bounded channels in the engine were not audited here.
