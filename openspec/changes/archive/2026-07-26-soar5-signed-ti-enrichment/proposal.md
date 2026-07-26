## Why

SOAR-4 shipped an `enrich` step whose own comment says what it is not: *"local context assembly, NOT
threat intelligence — no feed, no IOC lookup; SOAR-5 owns that and will replace this body."* An analyst
looking at an incident still cannot see the one fact that most often decides triage — whether the
destination involved is already known-bad.

The pieces are half-present and in the wrong shape. `internal/nips` parses an operator IOC feed
(domains, IPs, CIDRs, URI substrings), watches it for changes, and fetches it over a bounded conditional
GET — but the feed is **unsigned**, so anything that can write that file or answer that URL decides what
the gateway blocks and what the platform calls a threat. And nothing on the server side holds indicators
at all, so the control plane cannot enrich anything.

## What Changes

- **Signed feed ingest, verified BEFORE parsing.** Detached ed25519 signature over the feed bytes,
  operator-configured public key (the SEC-1 risk-signing key shape). The parser is the untrusted-input
  surface, so a feed that fails verification must never reach it — and a bad signature refuses the
  **whole** feed, never a partial load. A half-applied feed is an attacker's best outcome: drop the
  indicators that would catch them, keep the rest.
- **An explicit CSV format** (`kind,indicator`) alongside the native line format, chosen by an explicit
  format name — never by sniffing the content.
- **A server-side IOC store** (migration 033: `ioc_indicators` + `ioc_feeds` provenance). Ingest is
  transactional and **replaces** that feed's indicator set rather than appending: a feed is a SNAPSHOT,
  and an append-only store means a taken-down indicator is flagged forever and a withdrawn false positive
  can never be withdrawn.
- **Build once, literally.** Enrichment does not re-implement matching. `nips.Feed` gains
  `BuildFeed`/`Indicators`, the control plane materializes a `*nips.Feed` **from the store**, and
  enrichment calls the **same** `Feed.Match(host, dstIP, path)` the inline gateway engine uses. The
  parent-suffix domain semantics, the CIDR containment and the minimum-URI-indicator guard therefore have
  exactly one implementation and cannot drift between the inline and the analytical path.
- **Enrichment with no new column and no new privacy surface.** The observable is already persisted:
  XDR-5 gave every unified alert an evidence reference, and the verified event's `NetworkSubject` already
  carries `sni_host`, `dst_ip` and `http_path`. Enrichment walks incident → contributing alerts →
  evidence event → observables → `Feed.Match` → an `incident_annotations` row of kind `ti` naming the
  matched indicator and its feed.
- **Only VERIFIED events may steer enrichment** (D44). Unverified telemetry is not evidence, and letting
  it decide that an incident is TI-confirmed would let a forger manufacture confidence.
- **Wiring**: an operator-local `ingest-feed` subcommand (issuance-shaped, *not* a network route, per
  D51) plus an optional leader-only re-ingest loop over a configured signed feed, so the store stays
  fresh without a human.
- SOAR-4's `enrich` step now performs the TI lookup, and its "no threat-intel lookup performed" caveat
  goes away.

## Capabilities

### New Capabilities
- `threat-intel-store`: signed IOC feed ingest into a server-side indicator store with feed provenance,
  sharing one matcher with the inline network engine.

### Modified Capabilities
- `network-threat-intel`: adds the requirement that a feed may be signed and that verification precedes
  parsing, and that the feed's matcher is the single implementation used by both the inline and the
  analytical path.
- `playbook-orchestration`: the `enrich` step performs a threat-intel lookup against the IOC store and
  annotates matches, replacing the local-context-only behaviour.

## Impact

- **New code**: `internal/nips/signed.go` (verify-before-parse, CSV format, `BuildFeed`/`Indicators`),
  `internal/controlplane/threatintel.go` (store + ingest + `FeedFromStore`),
  `internal/controlplane/enrich_ti.go` (evidence → observables → match → annotation).
- **Migration 033**: `ioc_indicators`, `ioc_feeds`. Additive.
- **Wiring**: `openshield-server ingest-feed` subcommand; optional `OPENSHIELD_TI_FEED` +
  `OPENSHIELD_TI_FEED_KEY` leader-only re-ingest.
- **No proto change, no new dependency** (ed25519 is stdlib; the feed formats are hand-parsed).
- **Honest scope**, stated in the spec and the decision record: **no EPSS/KEV** (both key off a CVE
  identifier and nothing in the pipeline produces one — that needs a vulnerability scanner, which
  OpenShield does not have; a stub that always says "no CVE" would be worse than absence); **no
  geo/ASN** (needs a licensed GeoIP data file — a distribution decision, not a code one); **no STIX** (a
  STIX 2.1 bundle is a large untrusted-JSON surface that belongs behind the parser-sandbox discipline —
  the right shape is an external converter); no IOC ageing, confidence or TLP handling; no retro-hunt
  over historical alerts when a new feed lands; no signed URL fetch in this increment. And **enrichment
  annotates — it never raises an alert, changes a severity, or actuates**, because a TI hit is context
  for a human, and turning public threat-intel into automatic enforcement is how a poisoned feed becomes
  a denial of service.
