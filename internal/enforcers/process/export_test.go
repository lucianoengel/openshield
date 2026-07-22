package process

// NewKillEnforcerForTest builds a KillEnforcer with injected kill + trusted-identity resolver, so the
// self/critical guards can be tested without real processes, /proc, or root.
func NewKillEnforcerForTest(selfPID int, kill func(int) error, identify func(int) (ProcIdentity, error)) *KillEnforcer {
	return &KillEnforcer{selfPID: selfPID, kill: kill, identify: identify}
}
