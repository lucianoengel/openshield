// Package retain runs a periodic task until its context is cancelled — the shared
// ticker behind the retention purges (D81), so the server, engine and gateway
// binaries do not each reimplement the loop.
package retain

import (
	"context"
	"time"
)

// Loop invokes fn every interval until ctx is cancelled. It does NOT run fn
// immediately — the first invocation is after one interval, so a freshly-started
// binary is not doing a purge scan in its first moments. fn owns its own errors and
// logging (a purge is an operational event, not silent). A non-positive interval is
// treated as disabled (Loop returns immediately) so a misconfiguration cannot spin.
func Loop(ctx context.Context, interval time.Duration, fn func(context.Context)) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn(ctx)
		}
	}
}
