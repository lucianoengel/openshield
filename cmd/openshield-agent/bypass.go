package main

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/lucianoengel/openshield/internal/bypassguard"
)

// THE ENDPOINT HALF OF BYPASS PREVENTION (ZT-10), wired into the privileged agent.
//
// It lives here because this is the process that already holds privilege on the endpoint and already
// enforces locally (the exec gate, the file-open gate). It needs CAP_NET_ADMIN in addition to
// CAP_SYS_ADMIN, which is a real escalation of what the agent asks for and is why the guard is entirely
// opt-in and off by default.
//
// It adds NO parser to this binary: the rules are argv, the counter parse is a fixed-column integer scan,
// and neither goes near an attacker-controlled format. The agent's dependency ban (D13) stays true.

// bypassConfigured reports whether the guard has been asked for at all.
func bypassConfigured() bool {
	return strings.TrimSpace(os.Getenv("OPENSHIELD_ZTNA_PROTECTED")) != ""
}

// startBypassGuard installs the guard and starts reporting attempts. It returns false when the guard is
// not configured.
//
// A CONFIGURED-BUT-FAILING GUARD STOPS THE AGENT. That is the opposite of every other decision in this
// binary — the exec gate fails open, the IPC client fails open, an unreachable engine degrades rather
// than exits — and the difference is which way the failure points. Those fail open toward AVAILABILITY of
// a machine that is merely unmonitored. This one failing silently leaves an endpoint that an operator
// believes is fenced and is not, while the deployment record says the fence is up. A security control
// whose absence is invisible is worse than one that was never configured.
func startBypassGuard(ctx context.Context) bool {
	if !bypassConfigured() {
		return false
	}
	cfg := bypassguard.Config{
		Gateway:   strings.TrimSpace(os.Getenv("OPENSHIELD_ZTNA_GATEWAY_ADDR")),
		Protected: splitEnv("OPENSHIELD_ZTNA_PROTECTED"),
		AlsoAllow: splitEnv("OPENSHIELD_ZTNA_BYPASS_ALLOW"),
	}
	if err := bypassguard.Install(cfg, logf); err != nil {
		logf("ZTNA bypass guard NOT installed: %v", err)
		logf("refusing to continue with an unguarded endpoint that is configured as guarded — an " +
			"operator reading the deployment would believe the protected ranges are fenced")
		os.Exit(1)
	}
	logf("ZTNA bypass guard ACTIVE: %d protected range(s), gateway %s exempted. This is the ENDPOINT "+
		"half — the network half (the protected network accepting only the gateway) is where "+
		"enforcement binds, and root on this machine can remove these rules (D16).",
		len(cfg.Protected), cfg.Gateway)

	go reportBypassAttempts(ctx)
	go func() {
		<-ctx.Done()
		// Removed on a CLEAN shutdown only. An operator stopping the agent gets their machine back; an
		// agent that CRASHES leaves the guard in place, which is the fail-closed direction an access
		// control should fail in. The two cases genuinely differ and are treated differently rather
		// than picking one and calling it policy.
		if err := bypassguard.Remove(logf); err != nil {
			logf("ZTNA bypass guard teardown: %v", err)
		}
	}()
	return true
}

// reportBypassAttempts reports rejected bypass attempts, and ONLY when the count has moved.
//
// This is the half of the feature worth more than the blocking. A rejected connection to a protected
// service from this endpoint is a person or a process going around the broker — a finding regardless of
// whether it succeeded. A quiet endpoint says nothing; one whose user is probing says so every interval
// until they stop.
//
// A read FAILURE is reported too, and reported as a failure. "No attempts" and "we could not tell" are
// opposite answers to the only question this number is asked, and the reassuring one must never come
// from an error.
func reportBypassAttempts(ctx context.Context) {
	interval := envDuration("OPENSHIELD_ZTNA_BYPASS_REPORT_INTERVAL", time.Minute)
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	var last int64
	var errorsSeen int
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		n, err := bypassguard.Attempts()
		if err != nil {
			errorsSeen++
			// Reported on the FIRST failure and then every tenth, so a persistent fault stays visible
			// without a log line per tick drowning the thing it is reporting.
			if errorsSeen == 1 || errorsSeen%10 == 0 {
				logf("ZTNA bypass guard: cannot read the attempt count (%d consecutive): %v — this is "+
					"NOT zero attempts, it is no measurement", errorsSeen, err)
			}
			continue
		}
		errorsSeen = 0
		if n > last {
			logf("ZTNA BYPASS ATTEMPTS: %d packet(s) to protected ranges rejected on this endpoint "+
				"(+%d since the last report). Something here is trying to reach a protected service "+
				"without going through the gateway.", n, n-last)
			last = n
		}
	}
}
