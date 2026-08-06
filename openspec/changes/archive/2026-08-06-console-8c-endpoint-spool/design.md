# Design — CONSOLE-8c

## The drain loop is not the heartbeat loop

Folding the flush into the heartbeat ticker was tempting: it already exists, already ticks, and already
reports the spool depth. It is wrong. `OPENSHIELD_HEARTBEAT_INTERVAL<=0` disables the heartbeat, and an
operator who turns off a liveness signal has not asked for their telemetry to stop draining. The two
would be coupled invisibly until the day both mattered — which is the same day.

## Unconfigured stays unconfigured, but stops being silent

A spool is a real deployment choice: it costs disk, and an endpoint on a reliable network may decline it.
So the default is unchanged. What changes is that declining it is now a stated consequence rather than an
absent environment variable — the same rule the health report's problem list follows, where a problem
must say what it COSTS rather than which field it came from.

## An eviction is an error, not a warning

Below the ceiling the spool is doing its job. At the ceiling it is dropping the oldest records — exactly
the loss it exists to prevent — so that line is ERROR while the ordinary "drain stopped early, broker
still down" line is INFO. Logging the routine case loudly is how an operator learns to ignore the
important one.

## Stopping part-way through a drain is normal

`Drain` halts at the first send failure to preserve FIFO order, so a partial drain during a flapping
outage is the designed behaviour, not a fault. It is reported at INFO with the count sent, so a depth
that never falls is still visible.
