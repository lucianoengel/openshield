package dnsredirect

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"time"
)

const (
	defaultInterval = 5 * time.Second
	defaultFailures = 3
	probeTimeout    = 1 * time.Second
)

// Watchdog keeps the transparent redirect self-limiting: it installs the redirect only while the resolver
// answers, and removes it (falling back to direct DNS) once the resolver wedges — so a dead resolver never
// takes the host's name resolution down with it (the D73/D17 fail-open discipline applied to the redirect
// itself). A bypass is a degraded posture (unconfigured clients are no longer sinkholed) but strictly
// better than a wedged fleet.
type Watchdog struct {
	Port     int           // the resolver's UDP port (redirect target + default probe target)
	Mark     int           // the loop-break firewall mark
	Interval time.Duration // probe cadence; 0 → defaultInterval
	Failures int           // consecutive failed probes before bypass; 0 → defaultFailures
	Probe    func() bool   // resolver liveness; nil → the default DNS probe against 127.0.0.1:Port
	Log      *slog.Logger

	// install/remove are indirection points for tests; nil → the real Install/Remove.
	install func() error
	remove  func()

	installed           bool
	consecutiveFailures int
}

func (w *Watchdog) interval() time.Duration {
	if w.Interval > 0 {
		return w.Interval
	}
	return defaultInterval
}

func (w *Watchdog) failures() int {
	if w.Failures > 0 {
		return w.Failures
	}
	return defaultFailures
}

func (w *Watchdog) doInstall() error {
	if w.install != nil {
		return w.install()
	}
	return Install(w.Port, w.Mark, w.Log)
}

func (w *Watchdog) doRemove() {
	if w.remove != nil {
		w.remove()
		return
	}
	_ = Remove(w.Log)
}

func (w *Watchdog) probe() bool {
	if w.Probe != nil {
		return w.Probe()
	}
	return defaultProbe(w.Port)()
}

// Run installs the redirect, then probes the resolver on the interval — bypassing (removing) it after a
// run of failures and restoring it on recovery — until ctx is done, when it removes the redirect.
func (w *Watchdog) Run(ctx context.Context) {
	if err := w.doInstall(); err != nil {
		if w.Log != nil {
			w.Log.Error("dnsredirect: watchdog could not install the redirect — starting bypassed (resolver "+
				"still serves configured clients)", slog.String("err", err.Error()))
		}
		w.installed = false
	} else {
		w.installed = true
	}
	t := time.NewTicker(w.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			w.doRemove()
			return
		case <-t.C:
			w.step()
		}
	}
}

// step is one probe→transition, factored out so the state machine is testable without real time.
func (w *Watchdog) step() {
	if w.probe() {
		w.consecutiveFailures = 0
		if !w.installed {
			if err := w.doInstall(); err == nil {
				w.installed = true
				if w.Log != nil {
					w.Log.Warn("dnsredirect: resolver recovered — transparent redirect RESTORED")
				}
			}
		}
		return
	}
	w.consecutiveFailures++
	if w.consecutiveFailures >= w.failures() && w.installed {
		w.doRemove()
		w.installed = false
		if w.Log != nil {
			w.Log.Error("dnsredirect: resolver unhealthy — BYPASS: transparent redirect removed, DNS falling "+
				"back to direct resolution", slog.Int("consecutive_failures", w.consecutiveFailures))
		}
	}
}

// defaultProbe returns a liveness check that dials the resolver on 127.0.0.1:port, sends a well-formed DNS
// query, and reports whether any response arrives within probeTimeout. A response (NXDOMAIN or a relayed
// answer) proves the resolver is reading and answering.
func defaultProbe(port int) func() bool {
	return func() bool {
		c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return false
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(probeTimeout))
		// A minimal A query for "health.openshield.invalid" (id 0), which the resolver answers either way.
		q := []byte{0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
			6, 'h', 'e', 'a', 'l', 't', 'h', 10, 'o', 'p', 'e', 'n', 's', 'h', 'i', 'e', 'l', 'd',
			7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0, 0, 1, 0, 1}
		if _, err := c.Write(q); err != nil {
			return false
		}
		resp := make([]byte, 512)
		_, err = c.Read(resp)
		return err == nil
	}
}
