//go:build linux

package execaudit

import (
	"os"
	"strconv"
	"strings"
)

// readStartTicks reads a process's start-time (field 22 of /proc/<pid>/stat, in clock ticks since
// boot) — a stable per-process value that, with the pid, identifies the specific process instance
// for pid-reuse-safe termination (HIPS-7). It returns 0 on any error (the process already exited, or
// the field is unreadable), which the enforcement path treats as "identity unknown".
//
// The stat line is `pid (comm) state ...`; comm can contain spaces and parentheses, so fields are
// parsed AFTER the last ')': index 0 there is `state` (field 3), so `starttime` (field 22) is index 19.
func readStartTicks(pid int32) uint64 {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 20 {
		return 0
	}
	v, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	return v
}
