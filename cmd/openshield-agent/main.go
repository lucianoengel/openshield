// Command openshield-agent is the privileged inline-enforcement agent.
//
// It is NOT the observe path: the observe pipeline runs unprivileged as
// openshield-engine, which opens fanotify in NOTIFY mode itself (D52). This agent
// holds CAP_SYS_ADMIN and answers fanotify PERMISSION events, blocking an action
// while the triggering process is parked in TASK_UNINTERRUPTIBLE.
//
// Its first real function is HIPS-3 inline EXEC prevention: it marks
// FAN_OPEN_EXEC_PERM on watched paths and, for each exec, answers the kernel
// ALLOW/DENY under the fail-open watchdog, blocking a deny-listed or behaviorally
// suspicious binary BEFORE it runs. The exec decision is cheap (an operator
// deny-list + a behavioral score over exec metadata), so it fits the permission
// budget without content parsing — which is why exec is the first inline case
// (file-open DLP inline stays deferred per D49: classification cannot complete in
// the window).
//
// This binary MUST hold no content parser (a parser memory bug with this privilege
// is host compromise) — enforced by scripts/check-agent-deps.sh. That ban includes
// encoding/json, which is why this uses fmt to stderr, not log/slog (slog pulls
// encoding/json via its JSONHandler).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/execmon"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, "openshield-agent: "+format+"\n", a...) }

func main() {
	dirs := splitEnv("OPENSHIELD_EXEC_MONITOR_DIRS")
	if len(dirs) == 0 {
		logf("no exec-monitor configured. Set OPENSHIELD_EXEC_MONITOR_DIRS (comma-separated paths) + " +
			"OPENSHIELD_EXEC_DENY (deny-list file) to enable HIPS-3 inline exec prevention. " +
			"For the observe path, run openshield-engine.")
		// Exit non-zero so a service manager does not treat a do-nothing agent as healthy.
		os.Exit(2)
	}

	ev, err := buildEvaluator()
	if err != nil {
		logf("loading exec deny-list: %v", err)
		os.Exit(1)
	}

	mon, err := execmon.Open(dirs)
	if err != nil {
		logf("opening exec-permission monitor (need root + a permission-capable kernel): %v", err)
		os.Exit(1)
	}
	defer mon.Close()

	wd := &watchdog.Watchdog{
		SelfPID:   int32(os.Getpid()),
		Budget:    envDuration("OPENSHIELD_EXEC_BUDGET", 500*time.Millisecond),
		Responder: watchdog.FanotifyResponder{NotifyFD: mon.NotifyFD()},
		Evaluator: ev,
		Audit: func(_ context.Context, e watchdog.PermissionEvent, sev watchdog.Severity, reason string) error {
			logf("exec watchdog fail-open pid=%d path=%q severity=%d reason=%q", e.PID, e.Path, int(sev), reason)
			return nil
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logf("HIPS-3 inline exec prevention ACTIVE (dirs=%d budget=%s)", len(dirs), wd.Budget)
	if err := mon.Run(ctx, wd); err != nil && ctx.Err() == nil {
		logf("exec monitor stopped: %v", err)
		os.Exit(1)
	}
}

// buildEvaluator assembles the pure inline exec decider from the environment: a deny-list
// file (OPENSHIELD_EXEC_DENY) and an optional behavioral score floor
// (OPENSHIELD_EXEC_BEHAVIOR_FLOOR). At least one signal must be configured, so the agent
// does not run answering every exec ALLOW (a no-op enforcement is a misconfiguration).
func buildEvaluator() (execmon.DenyEvaluator, error) {
	var ev execmon.DenyEvaluator
	if f := strings.TrimSpace(os.Getenv("OPENSHIELD_EXEC_DENY")); f != "" {
		paths, bases, err := execmon.LoadDenyList(f)
		if err != nil {
			return ev, err
		}
		ev.DenyPaths, ev.DenyBasenames = paths, bases
	}
	if v := strings.TrimSpace(os.Getenv("OPENSHIELD_EXEC_BEHAVIOR_FLOOR")); v != "" {
		floor, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return ev, fmt.Errorf("bad OPENSHIELD_EXEC_BEHAVIOR_FLOOR %q: %w", v, err)
		}
		ev.BehaviorFloor = floor
	}
	// Application whitelisting (default-deny): OPENSHIELD_EXEC_ALLOW lists the ONLY binaries permitted to
	// execute; anything else (with a resolved path) is refused. Same format as the deny-list.
	if f := strings.TrimSpace(os.Getenv("OPENSHIELD_EXEC_ALLOW")); f != "" {
		paths, bases, err := execmon.LoadDenyList(f)
		if err != nil {
			return ev, err
		}
		ev.AllowPaths, ev.AllowBasenames = paths, bases
		logf("WARNING: application whitelisting (default-deny) is ON — only binaries in %s may execute; "+
			"an incomplete allowlist can break the host", f)
	}
	if len(ev.DenyPaths) == 0 && len(ev.DenyBasenames) == 0 && ev.BehaviorFloor <= 0 &&
		len(ev.AllowPaths) == 0 && len(ev.AllowBasenames) == 0 {
		return ev, fmt.Errorf("no exec signal configured: set OPENSHIELD_EXEC_DENY, OPENSHIELD_EXEC_ALLOW, and/or OPENSHIELD_EXEC_BEHAVIOR_FLOOR")
	}
	return ev, nil
}

func splitEnv(key string) []string {
	var out []string
	for _, d := range strings.Split(os.Getenv(key), ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
