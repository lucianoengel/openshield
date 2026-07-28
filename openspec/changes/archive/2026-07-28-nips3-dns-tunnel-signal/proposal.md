# The DNS tunnelling detector has never scored a query

## Why

`dns.TunnelScore` rates how likely a query name is a covert channel — long, high-entropy
subdomain labels carrying encoded data. It is written, documented, unit-tested, and has **no
caller outside its own package**. `dns.ToEvent` builds a NetworkSubject with a flow id, source
IP, port 53 and the queried name, and never computes the score. No shipped policy reads it.
Nothing downstream sees it.

The engine's DNS source states the opposite in its own doc comment: *"DNS-tunnelling detection
(dns.TunnelScore) become live rather than parser-only"*. It does not. The detector runs on
nothing.

This is the third instance of one shape:

- **D300** — no shipped policy read `input.threat`, so the NIPS-2 engine matched operator
  indicators, logged that it was active, and handed the match to a decision layer that ignored it.
- **D301** — the exec producer omitted a provenance field, so every engine-backed exec decision
  errored and the watchdog fail-opened, while every log line said inline prevention was active.
- This — the signal is computed nowhere, and the comment says it is live.

Each time, the feature exists everywhere except at the point where a signal becomes a decision,
and each time the logs report the feature working. That is the worst failure shape this project
has, and finding a third one means the pattern is worth naming rather than fixing case by case.

It surfaced from coverage measurement: `internal/connectors/dns` is at zero integration coverage,
so nothing had ever driven a live query through the pipeline.

## What Changes

- The policy input mapping computes a tunnel score for `EVENT_KIND_DNS_QUERY` events and exposes
  it as a typed, content-free input under its own key — `input.event.dns.tunnel_score` — following
  the CASB precedent, and NOT by overloading `input.event.behavioral` (see design).
- The default policy gains a rule that ALERTS on a high tunnel score. Alert, never block: a
  heuristic that automatically denies resolution turns one false positive into a resolution
  outage, which is the same reasoning as the NIPS-2 rule and D1's observe-only default.
- The threshold is a validated configuration setting, not a magic number — validated so that a
  value outside the score's reachable range is REFUSED at save rather than silently disabling the
  detector while the process logs it as enabled (the D303 trap).
- Integration coverage for the DNS source end to end: a real UDP query to a live listener,
  through classify → policy → decide, asserted on the AUDIT ROW.

## Impact

- Affected specs: `dns-sinkhole`
- Affected code: `internal/policy/mapping.go`, `internal/policy/default.rego`,
  `internal/config`, `cmd/openshield-engine`
- **No proto change.** `behavioral` is not a proto field — it is computed in the mapping layer
  from the process subject. A DNS score computed the same way needs no wire change.
- No migration. No new dependency.
- Existing policies are unaffected: the new input is absent for every event that is not a DNS
  query, exactly as `cloud` is absent for a non-catalogued host.
