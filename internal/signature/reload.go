package signature

import (
	"context"
	"os"
	"time"
)

// RulesetWatcher hot-reloads a content-signature ruleset file (NIPS-2): it captures the
// file's current modification time at construction, then on a timer reloads the file
// whenever its mtime CHANGES, handing the new Ruleset to an apply callback so the worker
// picks up new signatures without a restart.
//
// Baseline capture is SYNCHRONOUS (in NewRulesetWatcher), so a change written after
// construction is always observed as a change — the watch loop's asynchronous start
// cannot race a caller that writes the file right after starting it (the same discipline
// as nips.FeedWatcher).
type RulesetWatcher struct {
	path    string
	lastMod time.Time
}

// NewRulesetWatcher captures the file's current mtime as the baseline. It does NOT load
// the ruleset — the caller loads once at startup (fail-fast on a broken initial ruleset);
// the watcher handles only subsequent reloads.
func NewRulesetWatcher(path string) *RulesetWatcher {
	return &RulesetWatcher{path: path, lastMod: rulesetModTime(path)}
}

// Watch runs until ctx is done. On each tick it checks the file's mtime and, when it has
// CHANGED since the last observed version, re-parses the file and calls apply with the
// new Ruleset.
//
// Serve-stale on a bad edit: if a changed file fails to parse, onErr is called and the
// CURRENT ruleset is kept — a typo must never disarm the running engine. The bad
// version's mtime IS recorded, so the error is reported once, not every tick; when the
// operator fixes the file its mtime changes again and the fixed ruleset loads. apply and
// onErr must be safe to call from this goroutine.
func (w *RulesetWatcher) Watch(ctx context.Context, interval time.Duration, apply func(*Ruleset), onErr func(error)) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			mod := rulesetModTime(w.path)
			if mod.Equal(w.lastMod) {
				continue
			}
			w.lastMod = mod // record first, even on a parse failure, so a bad version reports once
			rs, err := LoadRuleset(w.path)
			if err != nil {
				if onErr != nil {
					onErr(err)
				}
				continue
			}
			apply(rs)
		}
	}
}

// rulesetModTime returns the file's modification time, or the zero time if it cannot be
// stat'd (a missing file reads as "unchanged from zero" so a transiently-absent file does
// not trigger a spurious reload; once it reappears with a real mtime it reloads).
func rulesetModTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}
