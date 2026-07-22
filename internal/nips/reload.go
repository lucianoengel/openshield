package nips

import (
	"context"
	"os"
	"time"
)

// FeedWatcher hot-reloads an IOC feed file (NIPS-2): it captures the file's current modification time
// at construction, then on a timer reloads the file whenever its mtime CHANGES, handing the new Feed to
// an apply callback so the running IPS picks up new indicators without a restart.
//
// Baseline capture is SYNCHRONOUS (in NewFeedWatcher), so a change written after construction is always
// observed as a change — the watch loop's asynchronous start cannot race a caller that writes the file
// right after starting it.
type FeedWatcher struct {
	path    string
	lastMod time.Time
}

// NewFeedWatcher captures the file's current mtime as the baseline. It does NOT load the feed — the
// caller loads once at startup (fail-fast on a broken initial feed); the watcher handles only
// subsequent reloads.
func NewFeedWatcher(path string) *FeedWatcher {
	return &FeedWatcher{path: path, lastMod: feedModTime(path)}
}

// Watch runs until ctx is done. On each tick it checks the file's mtime and, when it has CHANGED since
// the last observed version, re-parses the file and calls apply with the new Feed.
//
// Serve-stale on a bad edit: if a changed file fails to parse (a malformed line, a truncated write),
// onErr is called and the CURRENT feed is kept — a typo in the feed must never disarm the running
// engine. The bad version's mtime IS recorded, so the error is reported once, not every tick; when the
// operator fixes the file its mtime changes again and the fixed feed loads. An unchanged file is never
// re-parsed (cheap: a stat per tick). apply and onErr must be safe to call from this goroutine.
func (w *FeedWatcher) Watch(ctx context.Context, interval time.Duration, apply func(*Feed), onErr func(error)) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			mod := feedModTime(w.path)
			if mod.Equal(w.lastMod) {
				continue // unchanged since the last observed version — nothing to do
			}
			// Record the new mtime FIRST (even on a parse failure) so a persistently-bad version is
			// reported once, not every tick; a later fix changes the mtime and reloads.
			w.lastMod = mod
			feed, err := LoadFeed(w.path)
			if err != nil {
				if onErr != nil {
					onErr(err) // serve-stale: keep the current feed, report the bad edit
				}
				continue
			}
			apply(feed)
		}
	}
}

// feedModTime returns the file's modification time, or the zero time if it cannot be stat'd (a missing
// file reads as "unchanged from zero" so a transiently-absent file does not trigger a spurious reload;
// once it reappears with a real mtime it reloads).
func feedModTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}
