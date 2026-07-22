package execaudit

// SetStartTicks overrides the scanner's process start-time reader so a test can
// assert the CAPTURED value reaches the emitted event, without depending on a live
// /proc entry for the fabricated pid (HIPS-7).
func SetStartTicks(s *Scanner, fn func(pid int32) uint64) { s.startTicks = fn }
