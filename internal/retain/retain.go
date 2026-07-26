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

// DynamicLoop is Loop with an interval that is RE-EVALUATED every iteration (PLAT-5b).
//
// It exists because live-applied configuration is worthless if a running loop keeps using the interval it
// captured at start: a setting saved in the console would then not take effect until someone restarted
// the fleet, which is a config file with extra steps. The interval is read fresh each time, so a change
// takes effect on the next iteration.
//
// A non-positive interval is treated as "not configured" and the loop waits a short beat before asking
// again, so turning a feature on does not require a restart either.
func DynamicLoop(ctx context.Context, next func() time.Duration, fn func(context.Context)) {
	const idle = time.Second
	for {
		d := next()
		if d <= 0 {
			d = idle
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
		if ctx.Err() != nil {
			return
		}
		if next() > 0 {
			fn(ctx)
		}
	}
}
