# Design — SIEM-2 cross-host correlation

## The column, not a join

The originating host could in principle be recovered by joining a peer alert back to the
`fleet_telemetry` row that triggered it — but there is no stored link between them (the alert
is a derivation, not a foreign key into telemetry), and the derivation is deliberately kept
apart from received telemetry (D54). Recording the agent id **on the alert at write time** is
both simpler and truer to the model: the alert is the control plane's own detection, and "which
host did I detect this on" is a property of that detection, carried with it.

`agent_id` is the verified id from the signed envelope — the same value that attributes
`fleet_telemetry` — so the two aggregates use one attribution key. It is `NOT NULL DEFAULT ''`:
a pre-identity or legacy row has no host, and empty is the honest representation of that (it is
not a distinct host, so `count(DISTINCT agent_id)` over a set of empties is 1, matching "one
unknown origin", and a genuine multi-host burst is what raises the count above 1).

## MinHosts defaults to 1 — the burst rule is unchanged

`count(DISTINCT agent_id) >= MinHosts` in the `HAVING` clause is a no-op at `MinHosts <= 1`
(a group always has at least one agent id, even if empty). So the existing burst semantics are
preserved exactly, and the cross-host query is `MinHosts >= 2` — "the same subject anomalous on
two or more agents". `HostCount` is always returned, so an operator running the plain burst rule
still sees the spread.

## Why cross-host is a distinct signal, tested as such

The mutation that proves the facet is load-bearing: replace `count(DISTINCT agent_id)` with a
constant `1` (or `count(DISTINCT subject_id)`, which is 1 within a subject group). Under that
mutation `HostCount` is always 1 and the `MinHosts >= 2` filter selects nothing — so the
cross-host test, which expects a two-agent subject to be selected and a single-agent subject to
be excluded, fails. That is the isolate-the-guard discipline: the test must contain both a
same-subject-two-hosts case (selected) and a same-subject-one-host burst (excluded by
`MinHosts=2`), or the distinct-count is never exercised.

## Operator read surface

`agent_id` is added to the `PeerAlert` DTO and both read queries (`RecentPeerAlerts`,
`SearchPeerAlerts`) select it. This is a read-only widening of an existing surface; no new
filter is added (searching *by* host is a follow-up if wanted — the column now exists to support
it), keeping the change scoped to correlation.
