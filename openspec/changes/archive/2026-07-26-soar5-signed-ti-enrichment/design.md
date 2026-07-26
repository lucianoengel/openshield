## Context

`internal/nips` already holds the IOC matcher: a `Feed` of domains (parent-suffix matched), IPs, CIDRs and
URI substrings, with a file watcher, a bounded conditional-GET URL fetcher, and an R34-13 guard rejecting
degenerate short URI indicators. It is the inline engine the gateway blocks with. Two things are missing:
the feed is unsigned, and nothing server-side holds indicators, so the control plane cannot enrich.

The observable needed for enrichment is already persisted and needs no new column — the discipline that
made the intent id ride `Context.Version` rather than add a hashed ledger column (D254):

- XDR-5 put an evidence reference (`event_id`, `decision_id`) on every unified alert.
- XDR-5 also joins alerts to incidents through `incident_alerts`.
- The verified event's `NetworkSubject` already carries `sni_host`, `dst_ip`, `http_path`.

So enrichment is a walk over data that exists, not a new collection surface.

## Goals / Non-Goals

**Goals:**
- Detached-ed25519 feed verification that happens **before** parsing and refuses the feed as a whole.
- A server-side IOC store with feed provenance, replaced snapshot-wise on each ingest.
- **One matcher**: the store materializes a `*nips.Feed` and enrichment calls `Feed.Match`.
- Incident enrichment that annotates TI hits, reading observables only from VERIFIED events.
- Operator-local ingest (a subcommand), plus an optional leader-only refresh loop.

**Non-Goals:**
- **EPSS/KEV.** Both key off a CVE identifier, and nothing in the pipeline produces one — that requires a
  vulnerability scanner, a capability OpenShield does not have. A stub that always reports "no CVE" would
  be worse than the absence, because it looks like coverage.
- **Geo/ASN.** Needs a GeoIP database: a licensed data-file dependency, i.e. a distribution decision.
- **STIX.** A STIX 2.1 bundle is a large untrusted-JSON surface. The right shape is an external converter
  to a supported format, not a JSON parser inside the control plane.
- IOC ageing, confidence scores, TLP handling. An indicator is present or absent.
- Retro-hunting historical alerts when a new feed lands. Enrichment runs forward, at playbook time.
- A signed URL fetch (the unsigned conditional GET stays NIPS's).
- Any enforcement from a TI hit.

## Decisions

### Verify before parse, and refuse the whole feed

```go
func VerifyAndParse(data, sig []byte, pub ed25519.PublicKey, format Format) (*Feed, error)
```

`ed25519.Verify` runs first; on failure the function returns before touching the parser. Two properties
fall out, and both are the point:

1. A hostile feed never reaches the parsing code, which is the code an attacker would target.
2. Rejection is total. Per-line verification would apply exactly the attacker-chosen subset that verified,
   which is strictly worse than rejecting — they would drop the indicators naming their own infrastructure
   and keep everything else, and the store would look healthy.

*Alternative rejected:* an inline signature line in the feed format. That requires parsing to find the
signature, which inverts the ordering the whole design rests on.

### The format is named, not sniffed

`FormatNative` (`<kind> <indicator>`) and `FormatCSV` (`kind,indicator`). Sniffing lets a crafted file
choose which parser handles it — a small surface, but a free one to close.

### Snapshot semantics: ingest REPLACES a feed's rows

`DELETE FROM ioc_indicators WHERE feed = $1` then insert, in one transaction. A feed is a snapshot of what
its publisher currently asserts. Appending would mean a taken-down C2 domain stays flagged forever and a
withdrawn false positive can never be withdrawn — the store would only ever grow and only ever get less
trustworthy. Other feeds are untouched, so provenance stays meaningful.

### Matching is materialized through `nips.Feed`, never re-implemented

`nips.BuildFeed([]Indicator)` and `Feed.Indicators()` are added so a feed round-trips through a list. The
control plane's `FeedFromStore` selects the indicators and builds the same structure the gateway parses
into, and enrichment calls `Feed.Match(host, dstIP, path)`.

This is the ticket's "build once" and it is a correctness argument, not a tidiness one: the parent-suffix
domain rule (`evil.com` matches `c2.evil.com`, not `notevil.com`), the CIDR containment, and the
minimum-length URI guard are each a place where a second implementation would drift — and the drift would
be between *what gets blocked* and *what gets reported*, which is the worst possible pair to disagree.

*Alternative rejected:* matching in SQL. Suffix matching and CIDR containment are both expressible in
Postgres, but that is a second implementation of the semantics by definition. Feeds are small; loading one
is cheap.

### Observables come from VERIFIED events only

The evidence walk selects `FROM fleet_telemetry WHERE kind='event' AND event_id=$1 AND verified`, the same
predicate `originatingEvent` uses (D44). Unverified telemetry is not evidence. If it could steer
enrichment, anyone able to publish unsigned telemetry could manufacture a TI-confirmed incident — or bury
a real one under noise — without ever holding a key.

### A TI hit annotates and nothing else

No alert raised, no severity change, no lifecycle advance, no intent. A public feed is an assertion by a
third party, and an over-broad or poisoned entry (a CDN domain, a shared IP) would otherwise turn into
enforcement across the fleet. The annotation puts the fact in front of a human, which is what a TI hit is
worth.

### Ingest is a subcommand, not a route

`openshield-server ingest-feed <name> <file> [<sigfile>]`, alongside `issue-token` and `revoke` — the D51
shape. A network endpoint accepting indicator sets would let anything reaching it decide what the platform
calls a threat, which defeats the signature requirement standing next to it.

## Risks / Trade-offs

- **An over-broad indicator annotates everything** → annotation-only limits the damage to noise, and feed
  provenance names which feed to fix. Not solved: there is no per-indicator suppression.
- **A feed's key is the trust root** → the same exposure as the risk-signing key (SEC-1); signing proves
  ORIGIN, not correctness. A validly signed bad feed is indistinguishable from a good one, which is why a
  hit annotates rather than acts.
- **Loading the whole store per enrichment** → feeds are small (indicators, one per line, bounded by the
  existing fetch cap). If that stops being true, the fix is caching the materialized feed, not moving
  matching into SQL.
- **Unsigned feeds still load** → deliberate: existing deployments keep working, and the absence of a key
  is a visible configuration choice rather than a silent default. Named in the spec.
- **No retro-hunt** → an incident enriched before a feed named its destination stays un-annotated. Stated
  rather than implied; re-running the playbook is the operator's recourse.

## Migration Plan

Migration 033 adds `ioc_indicators` and `ioc_feeds`; nothing existing is altered, so rollback is dropping
two unused tables. With no feed ingested, `FeedFromStore` returns an empty feed which matches nothing, so
`enrich` behaves exactly as it did before this change.

## Open Questions

- Whether the gateway should also build its inline feed from the store (one distribution path instead of a
  file per host) — attractive, but it makes the gateway depend on the control plane for enforcement data,
  which is an availability decision that deserves its own round.
- Whether a signed URL feed should reuse `<url>.sig` by convention or carry the signature in a header —
  deferred with the URL fetch itself.
