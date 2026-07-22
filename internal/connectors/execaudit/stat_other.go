//go:build !linux

package execaudit

// readStartTicks is unsupported off Linux (no /proc) — the exec producer is Linux-first (D8). The
// event then carries start_ticks=0 ("identity unknown"), and the kill path degrades to best-effort.
func readStartTicks(int32) uint64 { return 0 }
