package casb

import (
	"context"
	"os"
	"time"
)

// CatalogWatcher hot-reloads a cloud-service catalog file (DLP-2): it captures the
// file's current modification time at construction, then on a timer reloads the file
// whenever its mtime CHANGES, handing the new Catalog to an apply callback so a change
// to a service's sanctioned status or host set takes effect without a restart.
//
// Baseline capture is SYNCHRONOUS (in NewCatalogWatcher), so a change written after
// construction is always observed as a change — the watch loop's asynchronous start
// cannot race a caller that writes the file right after starting it (the same
// discipline as nips.FeedWatcher and signature.RulesetWatcher).
type CatalogWatcher struct {
	path    string
	lastMod time.Time
}

// NewCatalogWatcher captures the file's current mtime as the baseline. It does NOT
// load the catalog — the caller loads once at startup (fail-fast on a broken initial
// catalog); the watcher handles only subsequent reloads.
func NewCatalogWatcher(path string) *CatalogWatcher {
	return &CatalogWatcher{path: path, lastMod: catalogModTime(path)}
}

// Watch runs until ctx is done. On each tick it checks the file's mtime and, when it
// has CHANGED since the last observed version, re-parses the file and calls apply.
//
// Serve-stale on a bad edit: a changed file that fails to parse calls onErr and the
// CURRENT catalog is kept — a bad edit must never disarm the running classifier. The
// bad version's mtime IS recorded, so the error is reported once, not every tick.
func (w *CatalogWatcher) Watch(ctx context.Context, interval time.Duration, apply func(*Catalog), onErr func(error)) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			mod := catalogModTime(w.path)
			if mod.Equal(w.lastMod) {
				continue
			}
			w.lastMod = mod // record first, even on a parse failure, so a bad version reports once
			cat, err := LoadCatalog(w.path)
			if err != nil {
				if onErr != nil {
					onErr(err)
				}
				continue
			}
			apply(cat)
		}
	}
}

// catalogModTime returns the file's modification time, or the zero time if it cannot
// be stat'd (a transiently-absent file reads as "unchanged from zero" and does not
// trigger a spurious reload; once it reappears with a real mtime it reloads).
func catalogModTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}
