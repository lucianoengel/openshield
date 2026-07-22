// Package process enforces the HIPS process-control verdicts (Phase E, E3). It implements
// the EXISTING core.TargetedEnforcer — the process domain is the third after files and
// flows, and the interface is unchanged: the target is a pid (for KILL_PROCESS) or an exec
// handle (for DENY_EXEC), supplied by the caller, and the Decision carries only the verdict
// (D14/D39).
//
// KILL_PROCESS is dangerous: a wrong target takes down a legitimate process, so the kill
// enforcer applies the same fail-SAFE discipline as the fail-open watchdog — it REFUSES to
// kill pid ≤ 1 (the kernel and init) or its own process, and a missing/malformed target is
// an error, never a kill of something arbitrary. DENY_EXEC records a deny disposition an
// exec-permission handler applies (the flow-enforcer pattern), so the enforcer never itself
// answers a kernel permission event it does not own.
package process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// criticalNames are processes that must NEVER be killed by a HIPS verdict — killing one takes down
// the host (init/systemd), locks out remote access (sshd/login), or destroys the platform itself
// (the data store, the container runtime). These are matched against the REAL executable's basename
// (from /proc/<pid>/exe, HIPS-8), not the self-settable kernel `comm`, so the full binary names are
// used (e.g. systemd-journald, not the 15-char-truncated comm).
var criticalNames = map[string]bool{
	"systemd": true, "init": true, "sshd": true, "login": true, "agetty": true,
	"postgres": true, "postmaster": true, "dbus-daemon": true, "systemd-logind": true,
	"systemd-journald": true, "containerd": true, "dockerd": true, "kubelet": true, "conmon": true,
	"runc": true, "crio": true,
}

// ProcIdentity is a process's TRUSTED identity for the critical-process guard: its real executable
// path and that binary's ownership. The exe comes from /proc/<pid>/exe, which the kernel maintains
// and the process cannot forge (unlike comm/argv[0]). Exported so a test can inject one without /proc
// or root.
type ProcIdentity struct {
	ExePath       string
	RootOwned     bool // the executable file is owned by uid 0
	OtherWritable bool // the executable file is writable by group or other (mode & 022)
}

// isCriticalProcess reports whether a process must be protected from KILL, keyed on its TRUSTED
// identity (HIPS-8): only a ROOT-OWNED, non-other-writable executable whose basename is a critical
// name — or a fleet binary (basename begins "openshield") — is protected. A non-root attacker cannot
// create a root-owned binary, so cannot gain immunity by renaming its process to a critical name (the
// self-immunization the comm-based guard allowed). A root attacker is outside the host-control model
// (D16) and can defeat the enforcer regardless.
func isCriticalProcess(id ProcIdentity) bool {
	if !id.RootOwned || id.OtherWritable {
		return false
	}
	base := filepath.Base(id.ExePath)
	if strings.HasPrefix(base, "openshield") {
		return true
	}
	return criticalNames[base]
}

// KillEnforcer carries out KILL_PROCESS by terminating a process by pid.
type KillEnforcer struct {
	selfPID  int
	kill     func(pid int, startTicks uint64) error // injectable; the platform kill, which revalidates startTicks (HIPS-7)
	identify func(pid int) (ProcIdentity, error)     // trusted identity for the critical-process guard; injectable
}

// NewKillEnforcer builds the enforcer with the platform's real kill and this process's pid
// as the self-protection guard.
func NewKillEnforcer() *KillEnforcer {
	return &KillEnforcer{selfPID: os.Getpid(), kill: platformKill, identify: procIdentityOf}
}

func (*KillEnforcer) Capabilities() []corev1.Action {
	return []corev1.Action{corev1.Action_ACTION_KILL_PROCESS}
}

// Enforce without a target cannot act — KILL_PROCESS needs a pid, supplied via EnforceTarget.
func (*KillEnforcer) Enforce(context.Context, *corev1.Decision) error {
	return fmt.Errorf("process: KILL_PROCESS needs a pid target")
}

// EnforceTarget kills the process named by target — a pid, optionally with the observation-time start
// identity as "pid:start_ticks" (HIPS-7). It fail-SAFES: pid ≤ 1 (kernel/init) and the enforcer's own
// pid are REFUSED, and a malformed target is an error — a process-killer must never fire on an
// unparseable or dangerous target.
func (k *KillEnforcer) EnforceTarget(_ context.Context, _ *corev1.Decision, target string) error {
	pidStr, ticksStr, hasTicks := strings.Cut(target, ":")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("process: KILL_PROCESS target %q is not a pid: %w", target, err)
	}
	var startTicks uint64
	if hasTicks {
		if startTicks, err = strconv.ParseUint(ticksStr, 10, 64); err != nil {
			return fmt.Errorf("process: KILL_PROCESS target %q has a bad start-ticks: %w", target, err)
		}
	}
	if pid <= 1 {
		return fmt.Errorf("process: refusing to kill pid %d (kernel/init)", pid)
	}
	if pid == k.selfPID {
		return fmt.Errorf("process: refusing to kill self (pid %d)", pid)
	}
	// Critical-process guard (HIPS-8): refuse to kill init/systemd/sshd/the DB/the fleet's own
	// binaries, identified by the TRUSTED executable identity (not the self-settable comm) so a
	// process cannot rename itself into immunity. If the identity can't be read the process is almost
	// certainly already gone, and the pid-reuse-safe kill below no-ops a dead instance.
	if id, err := k.identify(pid); err == nil && isCriticalProcess(id) {
		return fmt.Errorf("process: refusing to kill critical process %q (pid %d)", filepath.Base(id.ExePath), pid)
	}
	// The kill revalidates startTicks (HIPS-7): a pid whose current start-time no longer matches was
	// recycled, and is spared. startTicks==0 (unknown) falls back to a best-effort pid kill.
	return k.kill(pid, startTicks)
}

var _ core.TargetedEnforcer = (*KillEnforcer)(nil)

// ExecController is the seam an exec-permission handler exposes so the deny enforcer can
// record a DENY without itself answering the kernel (the flow-enforcer pattern, D73): the
// handler that owns the fanotify exec-permission fd applies the disposition.
type ExecController interface {
	Deny(execID string) error
}

// DenyEnforcer carries out DENY_EXEC by recording a deny disposition for an exec handle.
type DenyEnforcer struct {
	ctrl ExecController
}

func NewDenyEnforcer(ctrl ExecController) *DenyEnforcer { return &DenyEnforcer{ctrl: ctrl} }

func (*DenyEnforcer) Capabilities() []corev1.Action {
	return []corev1.Action{corev1.Action_ACTION_DENY_EXEC}
}

func (*DenyEnforcer) Enforce(context.Context, *corev1.Decision) error {
	return fmt.Errorf("process: DENY_EXEC needs an exec target")
}

// EnforceTarget records a deny for the exec handle named by target. A missing exec
// controller or an empty target is an error (D17) — a deny that goes nowhere would silently
// ALLOW the execution.
func (d *DenyEnforcer) EnforceTarget(_ context.Context, _ *corev1.Decision, target string) error {
	if d.ctrl == nil {
		return fmt.Errorf("process: DENY_EXEC has no exec controller to apply the deny")
	}
	if target == "" {
		return fmt.Errorf("process: DENY_EXEC needs an exec target")
	}
	return d.ctrl.Deny(target)
}

var _ core.TargetedEnforcer = (*DenyEnforcer)(nil)
