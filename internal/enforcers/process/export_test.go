package process

// NewKillEnforcerForTest builds a KillEnforcer with injected kill + comm resolver, so the
// self/critical guards can be tested without real processes or /proc.
func NewKillEnforcerForTest(selfPID int, kill func(int) error, nameOf func(int) (string, error)) *KillEnforcer {
	return &KillEnforcer{selfPID: selfPID, kill: kill, nameOf: nameOf}
}
