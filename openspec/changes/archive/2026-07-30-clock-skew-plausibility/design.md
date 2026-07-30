# Design

## The asymmetry is the whole design

| Direction | Decidable? | Why |
| --- | --- | --- |
| Future beyond tolerance | **Yes** | An event cannot be observed after it was received. No benign reading. |
| Past, any distance | **No** | Every spooled event has one (D40/D67). Network delay produces smaller ones. |

The first version bounded both, on the reasoning that a clock disagreeing with the server in either
direction is suspicious. It is — and it is also what a correctly functioning agent looks like after an
outage, which this product is specifically built to survive. Running it turned beacon detections from 1 to
0, which is the measurement that settled it.

There is no threshold that separates "implant lying backwards" from "agent was offline", because the
difference is not present in the data. The only thing that would separate them is a time reference the
endpoint does not author.

## Why this is still worth shipping

A narrower true claim beats a broad false one. And the future case is not academic: the sweep window looks
back from now, so events claiming to be from next week are outside it. An endpoint dating its contacts
forward removes itself from the analysis, and that costs nothing to close.

## Missing is not lying

An absent timestamp falls back to receipt time and is deliberately NOT counted as skew. Conflating "no data"
with "bad data" would bury the signal the counter exists to raise — the counter's purpose is to tell an
operator that some analysis is running on receipt time, and it is useless if every event without a timestamp
inflates it.

## The test had to be argued down

"A future-dated beacon is still detected" reads like the right end-to-end assertion and cannot work: seeding
inserts in a tight loop, so receipt times are milliseconds apart and the fallback has no rhythm.

It passed anyway — on rows left by an earlier test in a shared table. Clearing before seeding exposed it,
and that is the second time in this session a test passed on another test's leftovers. Worth stating as a
habit: **when a test passes alone and in the package, that is not isolation — clear the shared state BEFORE
seeding and see whether it still passes.**
