# Design — correlation correctness

## Empty is not a host

The cross-host signal (D131) counts distinct originating agents. A pre-identity alert has an empty
`agent_id`; counting it as a host inflates the distinct count, so a single-host subject with legacy
alerts crosses `MinHosts ≥ 2` and reads as lateral movement that never happened. `NULLIF(agent_id,
'')` maps the empty to NULL, which `count(DISTINCT …)` ignores — the count is real hosts only. The
test seeds one real host plus two empty-host alerts and asserts HostCount = 1 and exclusion at
MinHosts = 2; reverting the NULLIF makes HostCount = 2 and the false-positive returns.

## Fail loud, on every route

The alert `/search` already 400s a malformed filter; `/incidents` and `/overdue` did not — they
parsed with `if err == nil { use }`, silently keeping the default on bad input. That returns a
wider-than-asked result an investigator would trust. Both now reject a malformed param with 400,
and a valid request still succeeds. The served-mux test drives the real router with an operator cert.
