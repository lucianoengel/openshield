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
	"strconv"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// KillEnforcer carries out KILL_PROCESS by terminating a process by pid.
type KillEnforcer struct {
	selfPID int
	kill    func(pid int) error // injectable; defaults to the platform kill
}

// NewKillEnforcer builds the enforcer with the platform's real kill and this process's pid
// as the self-protection guard.
func NewKillEnforcer() *KillEnforcer {
	return &KillEnforcer{selfPID: os.Getpid(), kill: platformKill}
}

func (*KillEnforcer) Capabilities() []corev1.Action {
	return []corev1.Action{corev1.Action_ACTION_KILL_PROCESS}
}

// Enforce without a target cannot act — KILL_PROCESS needs a pid, supplied via EnforceTarget.
func (*KillEnforcer) Enforce(context.Context, *corev1.Decision) error {
	return fmt.Errorf("process: KILL_PROCESS needs a pid target")
}

// EnforceTarget kills the process named by target (a pid string). It fail-SAFES: pid ≤ 1
// (kernel/init) and the enforcer's own pid are REFUSED, and a non-numeric target is an
// error — a process-killer must never fire on an unparseable or dangerous target.
func (k *KillEnforcer) EnforceTarget(_ context.Context, _ *corev1.Decision, target string) error {
	pid, err := strconv.Atoi(target)
	if err != nil {
		return fmt.Errorf("process: KILL_PROCESS target %q is not a pid: %w", target, err)
	}
	if pid <= 1 {
		return fmt.Errorf("process: refusing to kill pid %d (kernel/init)", pid)
	}
	if pid == k.selfPID {
		return fmt.Errorf("process: refusing to kill self (pid %d)", pid)
	}
	return k.kill(pid)
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
