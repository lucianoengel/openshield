## Context

D206 gives an atomic, hot-swappable feed (`Gateway.threatFeed` is an `atomic.Pointer`, `SetThreatFeed`
swaps it, the per-request pipeline reads the current one) and a file `FeedWatcher` that serves-stale on
a bad edit. `ParseFeed(reader)` parses the feed format from any source. The only missing piece for a
remote feed is an HTTP SOURCE — structurally identical to how the JWKS refresher (ZT-2b/D182) added an
HTTP source behind unchanged verify logic.

## Goals / Non-Goals

**Goals:**
- Pull the IOC feed from an operator URL on a timer, live-swap on change, no restart.
- Serve-stale on a fetch failure OR a bad publish (never disarm the running IPS).
- Cheap steady state: a conditional request (ETag) means an unchanged feed is not re-downloaded/parsed.
- Bounded: a hostile/misconfigured URL cannot exhaust memory.

**Non-Goals:**
- STIX/TAXII protocol parsing — the feed format is unchanged (the operator's list at a URL); a TAXII
  poll envelope is a follow-on. This is the plain-URL source.
- Authenticated feeds (bearer/mTLS to the TI server) — a header/cert source is a follow-on; a public or
  network-restricted URL is the first cut.
- Replacing the file watcher — both coexist (a deployment picks a file OR a URL source).

## Decisions

1. **Conditional GET with ETag.** `FetchFeed(ctx, client, url, etag)` sends `If-None-Match: <etag>` when
   it has one; a `304 Not Modified` returns `changed=false` with no parse (steady-state cost is one
   cheap request); a `200` parses the body and returns the new ETag. A non-2xx/304 status is an error.
   This mirrors how a real TI feed server supports polling and keeps the refresh nearly free when the
   list has not changed.

2. **Bounded read.** The response body is read through an `io.LimitReader` at a few MB — a feed of
   indicators is small; a multi-hundred-MB response is an attack, not a feed. Over-limit is an error
   (serve-stale), not a truncated parse.

3. **`URLFeedWatcher` mirrors the file watcher.** `Watch(ctx, interval, apply, onErr)`: on each tick,
   `FetchFeed`; on `changed` → `apply(feed)`; on `!changed` → nothing; on error → `onErr` and KEEP the
   current feed. It holds the last ETag across ticks. Same serve-stale contract as D206, so a feed
   server outage or a malformed publish never disarms the IPS.

4. **Fail-fast initial, serve-stale after.** The gateway does an initial `FetchFeed` at startup; a
   failure there is fatal (a misconfigured feed URL should not start a silently-empty IPS), exactly like
   the initial local-file load. Only later refreshes serve-stale. The initial fetch seeds the ETag.

5. **Reuse the atomic swap.** `apply` is `gw.SetThreatFeed`, the D206 atomic pointer store — the new
   feed is live for the next request, in-flight requests keep theirs.

## Risks / Trade-offs

- **Outbound HTTP from the gateway.** The gateway is the egress chokepoint, so an outbound fetch is a
  dependency added consciously — but the JWKS refresher already established this pattern (an
  off-request-path timer fetch), and the fetch never runs on the request path. A default client timeout
  bounds a hung feed server.
- **A compromised feed server could publish a poisoned list.** Same trust as the file source (the
  operator owns the feed). Signing the feed (like the DLP signed indexes, D204) is a defensible
  follow-on; out of scope here. Serve-stale limits a bad-publish blast radius to "no NEW indicators",
  never "the IPS is disarmed".
- **No auth on the fetch (first cut).** A private feed behind a token/mTLS is a follow-on; a public or
  network-ACL'd URL is the initial target. Documented, not silently assumed.
