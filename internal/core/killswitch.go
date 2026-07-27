package core

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// The emergency disable (PLAT-9): "stop enforcing now".
//
// "How do I stop this?" is the question a CISO asks before "what does it detect?". Without this, every
// enforcement path can only be stopped by stopping the software — which also stops the detection and the
// audit trail, the worst possible trade during an incident the product itself is causing.
//
// FOUR PROPERTIES, each deliberate:
//
//  1. ONE IMPLEMENTATION, CONSULTED BY BOTH ENFORCEMENT CALL SITES. A switch honoured by the gateway and
//     forgotten by the endpoint is worse than none: the operator believes enforcement stopped, and it did
//     not.
//
//  2. IT SITS BETWEEN THE DECISION AND THE ENFORCER, and nowhere earlier. Classification, the policy and
//     the ledger all still run — only the enforcement call is skipped. A switch implemented earlier (drop
//     the event, skip classification) would destroy the record of what happened while enforcement was
//     off, which is exactly the period an operator will need to reconstruct. STOP ACTING; KEEP SEEING.
//
//  3. IT FAILS TOWARD ENFORCING — the opposite of the watchdog (D17), and the asymmetry is the point.
//     The watchdog fails open because a dead DLP that blocks everything gets uninstalled. Here, a read
//     error that silently disabled enforcement would let a corrupted file or a permissions change quietly
//     turn the product off across a fleet: an availability failure converted into a security failure. The
//     switch must be AFFIRMATIVELY engaged, and absence is never engagement.
//
//  4. EVERY SUPPRESSION IS COUNTED INDIVIDUALLY. "The switch is on" cannot answer "what did we not block
//     during those forty minutes", and a silent kill switch is indistinguishable from a product that has
//     stopped working.
type KillSwitch struct {
	mu       sync.RWMutex
	engaged  bool
	reason   string
	source   string
	since    time.Time
	changed  func(engaged bool, reason, source string)
	readErrs atomic.Int64
	// Suppressions counts enforcement calls this switch prevented — individually, because an operator
	// asking what was not blocked needs a number, not a state.
	Suppressions atomic.Int64
}

// NewKillSwitch returns a DISENGAGED switch. onChange, if set, is called when the state changes so the
// caller can record it — engaging or disengaging is itself an event worth a ledger entry.
func NewKillSwitch(onChange func(engaged bool, reason, source string)) *KillSwitch {
	return &KillSwitch{changed: onChange}
}

// Engage stops enforcement. Idempotent; a repeat with the same state does not re-notify.
func (k *KillSwitch) Engage(reason, source string) {
	k.set(true, reason, source)
}

// Disengage restores enforcement.
func (k *KillSwitch) Disengage(source string) {
	k.set(false, "", source)
}

func (k *KillSwitch) set(engaged bool, reason, source string) {
	k.mu.Lock()
	if k.engaged == engaged {
		k.mu.Unlock()
		return
	}
	k.engaged, k.reason, k.source, k.since = engaged, reason, source, time.Now()
	cb := k.changed
	k.mu.Unlock()
	if cb != nil {
		cb(engaged, reason, source)
	}
}

// Engaged reports the current state and why.
func (k *KillSwitch) Engaged() (bool, string) {
	if k == nil {
		return false, ""
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.engaged, k.reason
}

// ReadFailures counts times the switch's source could not be read. Each of those left enforcement ON, so
// the counter is how an operator learns the switch may not be reflecting their intent.
func (k *KillSwitch) ReadFailures() int64 {
	if k == nil {
		return 0
	}
	return k.readErrs.Load()
}

// SuppressEnforcement reports whether this Decision's enforcement must be skipped, and counts it.
//
// A nil switch never suppresses — a component that was never given one enforces normally, rather than
// silently doing nothing.
func (k *KillSwitch) SuppressEnforcement(d *corev1.Decision) (bool, string) {
	if k == nil || d == nil {
		return false, ""
	}
	engaged, reason := k.Engaged()
	if !engaged {
		return false, ""
	}
	// Only ENFORCING actions are suppressed. An alert-only decision is unaffected: there is nothing to
	// stop, and pretending otherwise would inflate the suppression count with decisions that never
	// enforced anything.
	if !enforcingAction(d.GetAction()) {
		return false, ""
	}
	k.Suppressions.Add(1)
	return true, reason
}

// enforcingAction reports whether an action DOES something to the subject, as opposed to recording it.
//
// Total over the closed Action set (D14) by construction: a new action must be added here deliberately,
// and the enum-completeness test that guards the Action set covers this the same way.
func enforcingAction(a corev1.Action) bool {
	switch a {
	case corev1.Action_ACTION_ALLOW, corev1.Action_ACTION_ALERT, corev1.Action_ACTION_UNSPECIFIED:
		return false
	default:
		// BLOCK, QUARANTINE_LOCAL, ENCRYPT_LOCAL, KILL_PROCESS, DENY_EXEC and any future enforcing verb.
		return true
	}
}

// BreakGlassFile is the conventional path an operator touches to stop enforcement on ONE host when the
// control plane is unreachable — which is exactly when they most need to.
//
// It requires root on that host, which D16 already treats as game-over for it, so this grants an attacker
// nothing they did not already have.
const BreakGlassFile = "/etc/openshield/EMERGENCY_DISABLE"

// WatchBreakGlass polls a break-glass file and engages/disengages accordingly.
//
// A read error that is not "does not exist" leaves the switch AS IT IS and is counted: an unreadable file
// must never be interpreted as either instruction. Absence means disengaged, because absence is the
// normal state and cannot be allowed to mean "stop enforcing".
func (k *KillSwitch) WatchBreakGlass(stop <-chan struct{}, path string, every time.Duration) {
	check := func() {
		body, err := os.ReadFile(path)
		switch {
		case err == nil:
			reason := "break-glass file"
			if s := trimReason(body); s != "" {
				reason = s
			}
			k.Engage(reason, "local:"+path)
		case os.IsNotExist(err):
			k.Disengage("local:" + path)
		default:
			// Unreadable: leave the switch alone and say so. Treating this as "engaged" would let a
			// permissions change disable the product; treating it as "disengaged" would let one silently
			// re-enable enforcement an operator had stopped.
			k.readErrs.Add(1)
		}
	}
	check()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			check()
		}
	}
}

func trimReason(b []byte) string {
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Install builds a KillSwitch, starts watching the local break-glass file, and returns it ready to be
// handed to an enforcement path.
//
// ONE FUNCTION, CALLED BY EVERY COMPONENT THAT ENFORCES, for the same reason there is one KillSwitch
// type: this file's first stated property is that a switch honoured by the gateway and forgotten by the
// endpoint is worse than none, and two hand-written wirings are how that divergence arrives. The fleet
// channel is subscribed by the caller, because only the caller knows whether it has a broker connection
// and a control-plane key.
//
// An empty path skips the local watcher — the switch still works, it just has no local source. That is a
// deliberate configuration, and the caller says so; it is not this function's place to decide that a host
// must have a break-glass file.
func Install(stop <-chan struct{}, breakGlassPath string, poll time.Duration,
	onChange func(engaged bool, reason, source string)) *KillSwitch {
	k := NewKillSwitch(onChange)
	if breakGlassPath != "" {
		if poll <= 0 {
			poll = 10 * time.Second
		}
		go k.WatchBreakGlass(stop, breakGlassPath, poll)
	}
	return k
}

// LoadPublicKey reads a raw ed25519 public key from a file.
//
// Here rather than in each command because the fleet-control key is loaded by every component that can be
// disabled, and a length check spelled per binary is a length check with a different answer per binary.
// The size check is the point: a truncated or wrong-format key file would otherwise become a subscriber
// that verifies nothing and refuses everything, which looks identical to a quiet channel.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key %s: %w", path, err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %s is %d bytes, want %d", path, len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}
