## 1. URL feed source (internal/nips)

- [x] 1.1 `FetchFeed(ctx, client, url, etag) (*Feed, newEtag string, changed bool, err error)` — bounded conditional GET; 304 → changed=false; 200 → ParseFeed; error on non-2xx / oversized / unparseable.
- [x] 1.2 A max response-size bound.
- [x] 1.3 `URLFeedWatcher` + `Watch(ctx, interval, apply, onErr)` — poll, atomic apply on change, serve-stale on error, hold the ETag across ticks.

## 2. Gateway wiring (cmd/openshield-gateway)

- [x] 2.1 When `OPENSHIELD_IOC_FEED_URL` is set: initial `FetchFeed` (fail-fast) → `SetThreatFeed`; seed the ETag.
- [x] 2.2 Start a `URLFeedWatcher` behind `OPENSHIELD_IOC_FEED_URL_RELOAD` (interval); apply = `SetThreatFeed`, onErr = log.

## 3. Tests (real HTTP via httptest; mutation-verified)

- [x] 3.1 `FetchFeed`: a 200 parses the served feed; a 304 → changed=false; a 500 / oversized / unparseable → error.
- [x] 3.2 `URLFeedWatcher`: a changed served feed is applied (new indicator matches); an unchanged (304) feed is not re-applied; a server error serves-stale (no apply, current kept).
- [x] 3.3 Mutations: `FetchFeed` ignores a non-200 status (parses anyway) → the error test FAILs; `Watch` applies on an error → the serve-stale test FAILs.

## 4. Gate + close

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile; restore binaries.
- [x] 4.2 `decisions.md` entry; sync delta spec into `openspec/specs/network-threat-intel`; `go test ./internal/doccheck/`.
- [x] 4.3 Archive; commit with trailers; `git pull --rebase` + push; update roadmap.
