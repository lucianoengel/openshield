package gateway

import (
	"context"
	"log/slog"
	"net"
	"time"
)

const defaultTProxyRetry = 5 * time.Second

// SuperviseTProxy runs the transparent inline plane under supervision: it (re)creates the listener, runs the
// rule-bound server (RunTProxyWithRules), and — when it stops for any reason other than a ctx cancel — waits
// a backoff and RE-ARMS, until ctx is cancelled. This self-heals the plane after a transient listener/accept
// failure, so a blip does not silently leave inline network prevention disabled for the rest of the
// process's life (D238 removes the stale rules on stop; this brings the plane back). A listener that cannot
// be created is retried the same way (fail-to-wire without giving up). Blocks until ctx is done.
func SuperviseTProxy(ctx context.Context, addr string, dports []int, mark, table int, retry time.Duration, newServer func() *TProxyServer, log *slog.Logger) {
	if retry <= 0 {
		retry = defaultTProxyRetry
	}
	arm := func(c context.Context) error {
		ln, err := ListenTransparent(addr)
		if err != nil {
			return err
		}
		RunTProxyWithRules(c, ln, newServer(), listenerPort(ln, addr), dports, mark, table, log)
		_ = ln.Close()
		return nil
	}
	superviseTProxy(ctx, arm, func(c context.Context) bool { return sleepCtx(c, retry) }, log)
}

// superviseTProxy is the seam-injected core (testable without root/listeners): arm-serve-backoff-rearm,
// exit only on ctx cancel.
func superviseTProxy(ctx context.Context, arm func(context.Context) error, backoff func(context.Context) bool, log *slog.Logger) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := arm(ctx); err != nil && ctx.Err() == nil && log != nil {
			log.Error("gateway: TPROXY inline plane could not arm — will retry after backoff", slog.String("err", err.Error()))
		}
		if ctx.Err() != nil {
			return
		}
		if log != nil {
			log.Warn("gateway: TPROXY inline plane stopped — re-arming after backoff")
		}
		if !backoff(ctx) {
			return // ctx cancelled during the wait
		}
	}
}

// sleepCtx waits d or until ctx is done; returns false if ctx finished first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// listenerPort resolves a listener's bound TCP port, falling back to parsing the configured address.
func listenerPort(ln net.Listener, addr string) int {
	if ta, ok := ln.Addr().(*net.TCPAddr); ok && ta.Port != 0 {
		return ta.Port
	}
	if _, p, err := net.SplitHostPort(addr); err == nil {
		var n int
		for _, c := range p {
			if c < '0' || c > '9' {
				return 0
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	return 0
}
