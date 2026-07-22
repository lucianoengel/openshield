//go:build !linux && !darwin

package process

import "fmt"

// platformKill is unsupported off Unix — the HIPS enforcer is Linux-first (D8). The enforcer still
// builds cross-platform (for the CI matrix); only the actuation is absent.
func platformKill(int) error {
	return fmt.Errorf("process: KILL_PROCESS is not supported on this platform")
}

// procIdentityOf is unsupported off Unix — the critical-process guard is Linux-first (D8).
func procIdentityOf(int) (ProcIdentity, error) {
	return ProcIdentity{}, fmt.Errorf("process: identity lookup unsupported on this platform")
}
