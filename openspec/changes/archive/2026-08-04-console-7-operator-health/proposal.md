# CONSOLE-7 · Operator-tier health

## Why

Every health fact this platform knows lives on `/metrics`, which sits on a SEPARATE listener behind a
SEPARATE constant-time bearer token (PLAT-4b). An operator session cannot reach any of it.

So the console's first tile has no data source, and the one question a fresh install actually raises has
no answer at operator tier: **an empty incident queue is indistinguishable from broken ingest.** That is
the most common way a pilot is abandoned — not because detection is poor, but because nobody can tell
whether the thing is running.

Leadership makes it worse. Only the leader runs the scheduled loops (PLAT-2b), so a follower legitimately
shows an empty queue and nothing anywhere says "you are talking to the standby".

## What

`GET /health` at the ANALYST tier — the lowest, because every operator using the console needs to know
whether the answers it gives them can be trusted.

It reports leadership, broker connection, the PLAT-10 ingest-repair counters, database reachability, the
PLAT-9 schema skew, and the newest external ledger anchor. Alongside the facts it carries a `problems`
list that names, for each thing that is wrong, what it COSTS — not merely what field it came from.

## What this is NOT

**A liveness probe.** It always answers 200 and lets the caller decide, for two reasons:

- **A follower is healthy.** Collapsing that into a status code marks every standby in a highly-available
  deployment as broken, which is how a team learns to ignore the check.
- **A single code cannot say what is wrong.** "Degraded" is not actionable; "the durable telemetry
  consumer has been rebuilt four times, so your broker is losing its state" is.

A load balancer wanting liveness should use TCP reachability of the port. Mixing the two audiences is how
a probe ends up gating production traffic on "is this the leader".
