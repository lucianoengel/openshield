package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/openipc"
	"github.com/lucianoengel/openshield/internal/agent/openmon"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// THE INLINE FILE-OPEN GATE (B2).
//
// A FAN_OPEN_PERM producer over configured DIRECTORIES, answered by the engine's pipeline over a
// socket. The agent reads a bounded prefix from the descriptor the kernel supplied with the event and
// sends those bytes; it never opens the file, because an open would raise a second permission event
// this same gate must answer — a deadlock inside a window that is uninterruptible.
//
// IT REQUIRES THE ENGINE. Unlike the exec gate, which has a static deny-list to fall back on, there is
// no local answer to "does this file contain sensitive content" — that judgement is the pipeline's. So
// a gate configured without a verdict socket is a gate that would fail open on every single event
// while reporting itself active, and it is refused rather than started.
func openGateConfigured() bool {
	return len(splitEnv("OPENSHIELD_OPEN_GATE_DIRS")) > 0
}

// runOpenGate starts the producer and blocks until ctx is done. It returns an error only for a
// configuration or setup failure; a running gate that loses its engine fails open, loudly, per event.
func runOpenGate(ctx context.Context) error {
	dirs := splitEnv("OPENSHIELD_OPEN_GATE_DIRS")
	sock := strings.TrimSpace(os.Getenv("OPENSHIELD_OPEN_IPC_SOCKET"))
	if sock == "" {
		return fmt.Errorf("OPENSHIELD_OPEN_GATE_DIRS is set but OPENSHIELD_OPEN_IPC_SOCKET is not. " +
			"The file-open gate has no local fallback — whether a file carries sensitive content is the " +
			"pipeline's judgement — so without the engine it would fail open on every event while " +
			"reporting itself active")
	}

	mon, err := openmon.Open(dirs)
	if err != nil {
		return fmt.Errorf("opening the file-open monitor (needs root and a permission-capable kernel): %w", err)
	}
	defer mon.Close()

	// THE PREFIX IS THE DEPLOYABILITY KNOB, and it is configurable because the measurement said it had
	// to be: the decision costs roughly 0.4ms per KiB, so the 64KiB ceiling is ~26ms per open. That is
	// fine for a directory of sensitive documents and ruinous for a source tree, and an operator who
	// cannot lower it has only the choice between a slow directory and no gate.
	prefix := envInt("OPENSHIELD_OPEN_PREFIX_BYTES", openipc.MaxPrefixLen)
	if prefix <= 0 || prefix > openipc.MaxPrefixLen {
		prefix = openipc.MaxPrefixLen
	}
	client := &openipc.Client{
		SocketPath: sock,
		Timeout:    envDuration("OPENSHIELD_OPEN_IPC_TIMEOUT", openipc.DefaultTimeout),
		MaxPrefix:  prefix,
	}
	defer client.Close()

	// THE BUDGET IS THE HOST'S SAFETY MARGIN, not a tuning knob. Every process opening a file in these
	// directories waits inside it, uninterruptibly, and when it elapses the watchdog ALLOWS and audits.
	// It is deliberately larger than the client's timeout so the common case is decided rather than
	// timed out, and small enough that a wedged engine costs latency rather than a hung desktop.
	budget := envDuration("OPENSHIELD_OPEN_BUDGET", 500*time.Millisecond)
	wd := &watchdog.Watchdog{
		SelfPID:   int32(os.Getpid()),
		Budget:    budget,
		Responder: watchdog.FanotifyResponder{NotifyFD: mon.NotifyFD()},
		Evaluator: client,
		Audit: func(_ context.Context, e watchdog.PermissionEvent, sev watchdog.Severity, reason string) error {
			logf("open watchdog fail-open pid=%d path=%q severity=%d reason=%q", e.PID, e.Path, int(sev), reason)
			return nil
		},
	}

	logf("B2 file-open gate ACTIVE on %s (verdicts from %s, budget=%s, prefix<=%dKiB ~%dms/open). "+
		"EVERY failure FAILS OPEN with a high-severity audit — a gate that failed closed would hang "+
		"every process on this host. The verdict comes from a BOUNDED PREFIX, so content past the "+
		"ceiling is not seen inline; the async tier classifies the whole file and contains it after.",
		strings.Join(dirs, ","), sock, budget, prefix>>10, (prefix>>10)*4/10)

	return mon.Run(ctx, wd)
}

// envInt reads an integer setting, falling back on anything unparseable.
//
// A fallback rather than a fatal, because this value is a performance knob and not a security one: a
// typo costs latency, and refusing to start would trade the whole gate for a misspelling. The declared
// field is range-checked by the config validation that runs before this (PLAT-5); this is the last line
// of defence, not the first.
func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
