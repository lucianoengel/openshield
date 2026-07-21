//go:build !linux && !darwin

package process

import "fmt"

// platformKill is unsupported off Unix — the HIPS enforcer is Linux-first (D8). The
// enforcer still builds cross-platform (for the CI matrix); only the actuation is absent.
func platformKill(pid int) error {
	return fmt.Errorf("process: KILL_PROCESS is not supported on this platform")
}
