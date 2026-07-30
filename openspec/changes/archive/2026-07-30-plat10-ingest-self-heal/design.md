# Design

## Why a timer beats the obvious hook

`nats.ReconnectHandler` is where this belongs on first reading, and it would have shipped a fix with a hole
in it. The failure being repaired is "the stream is not there", and that has causes with no disconnect
attached:

- an operator runs `nats stream rm`;
- a retention or limits change removes the asset;
- a cluster loses it without dropping any TCP connection.

In all of those the connection is healthy, no handler fires, and ingest is down silently — the original bug
with extra steps. A `ConsumerInfo` on a timer sees the state rather than an event about the state, so it
catches the causes nobody enumerated.

Cost: one round trip every 15s.

## Why the repair must be narrow

The tempting form is "if the check errored, rebuild". That turns every transient timeout into a teardown and
recreate of a working durable consumer — churning the thing that is currently delivering telemetry, on the
schedule of the network's worst moments. So only `ErrConsumerNotFound` and `ErrStreamNotFound` qualify.
Anything else is left alone, deliberately including errors that might *also* mean the stream is gone: a
false negative here costs one more poll interval, a false positive costs a working subscription.

## One definition of the subscription

`subscribeSignedDurable` is extracted rather than duplicated. The durable name, `ManualAck`, `AckExplicit`
and the Nak-with-backoff handler all have to be identical on a repair — a second copy would be correct on
the day it was written and wrong on the first day somebody edited one of them.

`sigSub` also moves out of the `subs` slice into its own field: everything in `subs` lives for the process,
and this is the one that gets replaced. Leaving it in the slice would mean the healer either mutated a slice
by index or leaked the dead subscription.

## Announce before repairing

The log line goes out *before* `EnsureTelemetryStream` is attempted. If the repair fails, the record still
shows that ingest went down and when — which is the property D31 actually asks for. A message emitted only
on success documents the recoveries and hides the outages.

Repair failures are counted separately from repairs (`IngestRepairFailures`), so "we healed twice" and "we
tried and could not" are distinguishable without reading the log.

## What the mutation had to prove, and a check that lied

Healing disabled → the empty-broker scenario fails on the spool never draining (198s against a 37s pass).

The compile check reported `MUTANT_COMPILES=no` and was wrong: an early `return` makes the rest of the
function unreachable, which `go vet` rejects and the **compiler accepts**. `go build` confirms the mutant
built, and the 198-second timeout could only have come from a working binary. Recorded because D359's lesson
is that the check itself must not be able to lie, and here the check I used to guard against a false
mutation result was itself measuring the wrong thing — `go vet` is not `go build`.
