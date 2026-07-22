package nips

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// applied is a concurrency-safe recorder for the feeds WatchFeed hands back.
type applied struct {
	mu    sync.Mutex
	feeds []*Feed
	errs  []error
}

func (a *applied) apply(f *Feed) { a.mu.Lock(); a.feeds = append(a.feeds, f); a.mu.Unlock() }
func (a *applied) onErr(e error) { a.mu.Lock(); a.errs = append(a.errs, e); a.mu.Unlock() }
func (a *applied) lastFeed() *Feed {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.feeds) == 0 {
		return nil
	}
	return a.feeds[len(a.feeds)-1]
}
func (a *applied) errCount() int { a.mu.Lock(); defer a.mu.Unlock(); return len(a.errs) }

// feedGen makes each writeFeed stamp a STRICTLY-increasing, well-separated mtime independent of the
// wall clock, so the watcher reliably sees each edit as "changed" regardless of filesystem mtime
// granularity or how close together the writes happen.
var feedGen int64

func writeFeed(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	feedGen++
	mt := time.Unix(1_700_000_000+feedGen*3600, 0)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	// A generous deadline: the watcher is a background ticker goroutine, which can be starved when the
	// full test suite saturates the CPU — so this is timing-robust, not timing-tight.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// TestWatchFeedReloadsOnChange (NIPS-2): a changed feed file is re-parsed and handed to apply, so the
// running engine picks up new indicators without a restart.
//
// Mutation: if WatchFeed ignored the mtime change (never reloaded), lastFeed stays nil → FAIL.
func TestWatchFeedReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ioc.feed")
	writeFeed(t, path, "domain evil.com\n")

	var rec applied
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Baseline is captured synchronously here, so a change written below is always seen as a change.
	go NewFeedWatcher(path).Watch(ctx, 15*time.Millisecond, rec.apply, rec.onErr)

	// No change yet → no reload (WatchFeed baselines the startup mtime). Generous settle time so the
	// watcher has certainly read its baseline before we assert (and before the change below).
	time.Sleep(200 * time.Millisecond)
	if rec.lastFeed() != nil {
		t.Fatal("WatchFeed reloaded an unchanged file")
	}

	// Change the file → a reload with the new indicators.
	writeFeed(t, path, "domain evil.com\nip 1.2.3.4\ndomain worse.example\n")
	waitUntil(t, func() bool { f := rec.lastFeed(); return f != nil && f.Size() == 3 })
	if m := rec.lastFeed().Match("worse.example", "", ""); len(m) == 0 {
		t.Fatal("the reloaded feed does not contain the newly-added indicator")
	}
}

// TestWatchFeedServesStaleOnBadEdit (NIPS-2): a changed-but-malformed feed is reported via onErr and
// NOT applied — a feed typo must never disarm the running IPS. A subsequent GOOD edit still loads.
//
// Mutation: if WatchFeed applied a feed even on a parse error, a malformed edit would be handed to
// apply → the "no apply on error" assertion FAILs.
func TestWatchFeedServesStaleOnBadEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ioc.feed")
	writeFeed(t, path, "domain evil.com\n")

	var rec applied
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Baseline is captured synchronously here, so a change written below is always seen as a change.
	go NewFeedWatcher(path).Watch(ctx, 15*time.Millisecond, rec.apply, rec.onErr)

	// First establish a LIVE reload — this deterministically proves the watcher has read its baseline
	// and is processing changes, so the bad edit below cannot race the baseline read.
	writeFeed(t, path, "domain evil.com\ndomain two.example\n")
	waitUntil(t, func() bool { f := rec.lastFeed(); return f != nil && f.Size() == 2 })

	// A malformed edit (unknown kind) → an error, no NEW apply (the last good feed, size 2, is kept).
	writeFeed(t, path, "notakind something\n")
	waitUntil(t, func() bool { return rec.errCount() >= 1 })
	if f := rec.lastFeed(); f == nil || f.Size() != 2 {
		t.Fatalf("WatchFeed applied a malformed feed (last size %v) — the running IPS would be disarmed by a typo", f)
	}

	// A subsequent GOOD edit loads (the watcher recovered from the bad version).
	writeFeed(t, path, "domain evil.com\nip 9.9.9.9\ndomain three.example\n")
	waitUntil(t, func() bool { f := rec.lastFeed(); return f != nil && f.Size() == 3 })
}
