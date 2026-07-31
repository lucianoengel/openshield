//go:build !linux

package bypassguard

// Logf mirrors the Linux signature. It is a plain function rather than a *slog.Logger because log/slog
// pulls encoding/json, which the privileged agent must not hold (D13).
type Logf func(format string, args ...any)

// Install refuses on a non-Linux host rather than reporting success.
//
// A silent no-op would be the worst available outcome: the operator configures the guard, the process
// says nothing, and the endpoint is unguarded while the deployment record says otherwise. The guard's own
// premise is that a gap must never be silent.
func Install(Config, Logf) error { return errUnsupported }

// Remove is a no-op where nothing can have been installed.
func Remove(Logf) error { return nil }

// Attempts cannot be answered here, and says so rather than returning a reassuring zero.
func Attempts() (int64, error) { return 0, errUnsupported }
