## Why

D206 made the NIPS-2 IOC feed hot-reload from a LOCAL file — a new indicator no longer needs a
restart. But the roadmap still flags "no remote feed pull (STIX/TAXII)": operators run threat-intel as
a served feed (a URL a TI platform publishes, a mirror of an OTX/abuse.ch list), and today that means a
cron job writing the file locally. Pulling the feed directly closes the last-mile: OpenShield refreshes
its blocklist straight from the operator's feed URL, on a timer, without a sidecar.

## What Changes

- **A URL feed source** (`internal/nips`): `FetchFeed(ctx, client, url, etag)` does a bounded HTTP GET
  with conditional `If-None-Match`, returning the parsed `Feed` on a 200, "not modified" on a 304 (so
  an unchanged feed is never re-parsed), and an error on a non-2xx / oversized / unparseable response.
- **A URL watcher** (`URLFeedWatcher.Watch`): mirrors the D206 file watcher — poll the URL on a timer,
  swap the feed atomically on a CHANGED body, and **serve-stale on a fetch or parse failure** (a feed
  server outage or a bad publish must NEVER disarm the running IPS — the current feed keeps serving).
- **Wired in the gateway** behind `OPENSHIELD_IOC_FEED_URL` + `OPENSHIELD_IOC_FEED_URL_RELOAD`
  (interval): the initial fetch is fail-fast (a misconfigured URL aborts startup, like the initial
  local file); later refreshes serve-stale. The existing atomic `SetThreatFeed` swap (D206) makes the
  new feed live for the next request with no restart.

This reuses D206's atomic feed swap and the `ParseFeed` parser; only the SOURCE is new (a URL instead
of a file), exactly as the JWKS refresher (ZT-2b) added an HTTP source behind the same verify logic.

## Capabilities

### New Capabilities
<!-- none: this extends the existing network-threat-intel capability with a remote SOURCE. -->

### Modified Capabilities
- `network-threat-intel`: the IOC feed can be pulled from a remote URL on a timer (in addition to a
  local file), serve-stale on a fetch/parse failure.

## Impact

- `internal/nips`: `FetchFeed` (bounded GET + conditional request) + `URLFeedWatcher` (poll + atomic
  apply + serve-stale) + a max response-size bound.
- `cmd/openshield-gateway`: fetch the initial feed from `OPENSHIELD_IOC_FEED_URL` (fail-fast) and start
  a `URLFeedWatcher` behind `OPENSHIELD_IOC_FEED_URL_RELOAD`.
- No proto change, no core change, no new dependency (net/http only).
