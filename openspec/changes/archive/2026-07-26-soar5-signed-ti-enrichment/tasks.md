## 1. Feed: signing, formats, round-trip

- [x] 1.1 `internal/nips`: `Indicator{Kind,Value}`, `Feed.Indicators()`, `BuildFeed([]Indicator)` — so a
      feed round-trips through a list and the store can rebuild the identical matcher.
- [x] 1.2 `Format` (`native`, `csv`) with an explicit selector; a CSV parser reusing the same per-indicator
      validation (including the R34-13 minimum URI length). No content sniffing.
- [x] 1.3 `VerifyAndParse(data, sig, pub, format)`: ed25519 verification runs BEFORE the parser and a
      failure returns without parsing. `LoadSignedFeed(path, sigPath, pub, format)` for the file case.
- [x] 1.4 Tests: a tampered feed is refused and never parsed (**mutation:** verify after parse → the
      parser runs on hostile bytes → FAILS); a signature from another feed does not transfer; the
      round-trip feed matches identically to the parsed one (**mutation:** drop CIDRs from `Indicators()`
      → the rebuilt feed misses a CIDR hit → FAILS); an unsigned load still works.

## 2. IOC store

- [x] 2.1 Migration `033_threat_intel.sql`: `ioc_indicators` (kind, value, feed, PK (kind,value,feed)) and
      `ioc_feeds` (name, digest, indicator_count, ingested_at). Additive; add both to every test drop list.
- [x] 2.2 `internal/controlplane/threatintel.go`: `IngestFeed(ctx, name, data, sig, pub, format)` —
      verify → parse → in ONE transaction delete that feed's rows, insert the new set, record provenance.
- [x] 2.3 `FeedFromStore(ctx)` materializing a `*nips.Feed` from `ioc_indicators`.
- [x] 2.4 Tests: a bad signature stores nothing; a re-ingest REPLACES so a withdrawn indicator disappears
      (**mutation:** append instead of replace → the withdrawn indicator survives → FAILS); one feed's
      ingest leaves another's indicators alone; provenance is recorded.

## 3. Enrichment

- [x] 3.1 `internal/controlplane/enrich_ti.go`: incident → `incident_alerts` → `unified_alerts.event_id`
      → VERIFIED `fleet_telemetry` event → `NetworkSubject` observables → `Feed.Match` → a `ti`
      annotation naming the indicator and feed. No match ⇒ no annotation.
- [x] 3.2 Wire it into SOAR-4's `enrich` step and delete the "no threat-intel lookup performed" caveat.
- [x] 3.3 Tests: a known-bad SUBDOMAIN gets a `ti` annotation naming indicator+feed (**mutation:** match
      the host exactly rather than through the shared matcher → the subdomain misses → FAILS); a clean
      incident gets none; an UNVERIFIED event carrying a known-bad domain is ignored (**mutation:** drop
      `AND verified` → FAILS); a TI hit changes no severity, state or alert (annotation only).

## 4. Wiring

- [x] 4.1 `openshield-server ingest-feed <name> <file> [<sig>]` subcommand (alongside `issue-token` /
      `revoke`), reading the public key from `OPENSHIELD_TI_FEED_KEY`. No HTTP route accepts feed content.
- [x] 4.2 Optional leader-only re-ingest loop over `OPENSHIELD_TI_FEED` on `OPENSHIELD_TI_FEED_INTERVAL`,
      failing loudly and never fatally.

## 5. Gate and land

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 5.2 Record D257 in `docs/decisions.md` with the honest scope (no EPSS/KEV, no geo/ASN, no STIX, no
      ageing, no retro-hunt, annotate-never-enforce, unsigned feeds still load).
- [x] 5.3 Update `docs/architecture-roadmap.md`: SOAR-5 → DONE with residuals; refresh the SOAR maturity
      line and NIPS-2's signed-feed note.
- [x] 5.4 Sync delta specs into `openspec/specs/` and archive the change.
