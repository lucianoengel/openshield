package nips

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxFeedResponse bounds a fetched feed body. An IOC list is small (indicators, one per line); a
// multi-hundred-MB response is an attack or a misconfiguration, not a feed.
const maxFeedResponse = 8 << 20

// FetchFeed pulls the IOC feed from url with a bounded, CONDITIONAL GET (NIPS-2 remote source). When
// etag is non-empty it sends If-None-Match, so a 304 returns (nil, etag, false, nil) — the feed is
// unchanged and is NOT re-parsed (cheap steady state). A 200 parses the body and returns the new feed,
// the response ETag, and changed=true. A non-2xx/304 status, an oversized body, or an unparseable feed
// is an error (the caller serves-stale). The client's timeout bounds a hung feed server.
func FetchFeed(ctx context.Context, client *http.Client, url, etag string) (*Feed, string, bool, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, etag, false, fmt.Errorf("nips: building feed request: %w", err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, etag, false, fmt.Errorf("nips: fetching feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, false, nil // unchanged — keep the current feed, no re-parse
	}
	if resp.StatusCode != http.StatusOK {
		return nil, etag, false, fmt.Errorf("nips: feed URL returned status %d", resp.StatusCode)
	}
	// Bound the read: maxFeedResponse+1 so an over-limit body is detected rather than silently truncated
	// into a parseable-but-wrong feed.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedResponse+1))
	if err != nil {
		return nil, etag, false, fmt.Errorf("nips: reading feed body: %w", err)
	}
	if len(body) > maxFeedResponse {
		return nil, etag, false, fmt.Errorf("nips: feed body exceeds %d bytes", maxFeedResponse)
	}
	feed, err := ParseFeed(bytes.NewReader(body))
	if err != nil {
		return nil, etag, false, err // a bad publish — serve-stale, do not disarm the IPS
	}
	return feed, resp.Header.Get("ETag"), true, nil
}

// URLFeedWatcher hot-reloads the IOC feed from a remote URL (NIPS-2). Like the file FeedWatcher it
// serves-stale on failure and swaps atomically via the apply callback; it holds the last ETag so an
// unchanged feed costs one conditional request and no parse.
type URLFeedWatcher struct {
	url    string
	client *http.Client
	etag   string
}

// NewURLFeedWatcher builds a watcher for url. initialEtag seeds the conditional request from the
// startup fetch (so the first tick after startup does not re-download an unchanged feed). client may be
// nil (a default-timeout client is used).
func NewURLFeedWatcher(url string, client *http.Client, initialEtag string) *URLFeedWatcher {
	return &URLFeedWatcher{url: url, client: client, etag: initialEtag}
}

// Watch polls the URL on a timer until ctx is done. On a CHANGED feed it calls apply; on "not modified"
// it does nothing; on a fetch or parse error it calls onErr and KEEPS the current feed (serve-stale).
func (w *URLFeedWatcher) Watch(ctx context.Context, interval time.Duration, apply func(*Feed), onErr func(error)) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			feed, newEtag, changed, err := FetchFeed(ctx, w.client, w.url, w.etag)
			if err != nil {
				if onErr != nil {
					onErr(err)
				}
				continue // serve-stale
			}
			w.etag = newEtag
			if changed {
				apply(feed)
			}
		}
	}
}
