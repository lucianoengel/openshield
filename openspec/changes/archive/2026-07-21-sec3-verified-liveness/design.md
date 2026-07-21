## Context

Liveness and views read fleet_telemetry, which holds both verified (signed, attributable) and
unverified (self-asserted) rows. Counting the unverified rows is what let a forger keep an
agent alive.

## Goals / Non-Goals

**Goals:** liveness from verified telemetry over the enrolled roster; DB-error honesty.

**Non-Goals:** removing the unsigned subscriptions; view filtering (small follow-up).

## Decisions

**Roster-authoritative, verified-only.** `Overdue` starts from `agent_identities` (the enrolled,
non-revoked fleet) and LEFT JOINs the last VERIFIED telemetry. An enrolled agent with no verified
telemetry has a NULL last-seen → maximally overdue (correct — it is silent or forged). This also
survives fleet-telemetry purge, because the roster is the identity table, not the telemetry.

**Error is not absence (SEC-11).** `LastSeen` scans `max(received_at)` into a `*time.Time`: nil is
genuinely-never-seen, a query error is returned as an error. A down DB must be a loud failure, not
a silent "the whole fleet is unknown" — the recurring error-vs-absence honesty rule (D28).

**Production already signs heartbeats.** The fleet-agent publishes via SignedPublisher
(verified=true), so verified liveness is not a regression — it removes the forgeable unsigned path
from the authoritative view.

## Risks / Trade-offs

- **An agent that only ever sends unsigned telemetry now reads as overdue.** Correct: unsigned
  telemetry is not attributable, so it cannot vouch for liveness. Agents must sign (they do).
- **Unsigned rows still accumulate** until the subscriptions are deprecated (a follow-up); they no
  longer affect liveness or authoritative views.
