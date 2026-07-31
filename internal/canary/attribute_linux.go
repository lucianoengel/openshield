//go:build linux

package canary

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Attribute names the processes holding descriptors open under dir (HIPS-8).
//
// max bounds how many suspects are returned; the rest are still SCANNED, so the counts describe the whole
// system rather than the prefix that fitted. A non-positive max means all of them.
//
// SELF IS ALWAYS EXCLUDED, and that is not hygiene. This engine reads the canaries itself to measure their
// entropy — it is, briefly and by design, a process holding canary files open. Attributing a ransomware
// detection to the detector would be the most embarrassing possible false positive, and it is the one
// this code is structurally most likely to produce.
func Attribute(dir string, max int) Attribution {
	att := Attribution{Supported: true}
	dir = filepath.Clean(dir)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return Attribution{} // no /proc: Supported stays false, so the caller cannot read this as "clean"
	}
	self := os.Getpid()

	var found []Suspect
	for _, e := range entries {
		pid, perr := strconv.Atoi(e.Name())
		if perr != nil || pid <= 0 {
			continue // not a process directory
		}
		if pid == self {
			continue
		}
		att.Scanned++
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, ferr := os.ReadDir(fdDir)
		if ferr != nil {
			// A process that EXITED between the listing and this read is normal churn on a busy host and
			// is not an obstruction — counting it would make Unreadable meaningless on every machine.
			// Anything else (permission, in practice) is.
			if os.IsNotExist(ferr) {
				continue
			}
			att.Unreadable++
			continue
		}
		open := 0
		for _, fd := range fds {
			target, rerr := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if rerr != nil {
				continue // the descriptor closed under us; ordinary
			}
			if underTree(target, dir) {
				open++
			}
		}
		if open == 0 {
			continue
		}
		found = append(found, Suspect{
			PID:        pid,
			Exe:        readlinkQuiet(filepath.Join("/proc", e.Name(), "exe")),
			StartTicks: startTicks(e.Name()),
			OpenPaths:  open,
		})
	}

	att.Suspects = rank(found)
	if max > 0 && len(att.Suspects) > max {
		att.Suspects = att.Suspects[:max]
	}
	return att
}

// readlinkQuiet resolves a symlink or returns "" — an unreadable /proc/<pid>/exe is expected for a
// process owned by another user, and is reported as an unnamed suspect rather than dropped.
func readlinkQuiet(path string) string {
	v, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(v, " (deleted)")
}

// startTicks reads field 22 of /proc/<pid>/stat, the process start time in clock ticks.
//
// The parse starts AFTER the final ')' rather than splitting the whole line, because field 2 is the
// executable's comm IN PARENTHESES and a process is free to have spaces or a ')' in its name. Splitting
// on whitespace shifts every later field for exactly the processes that chose a name to make that happen
// — and this value is what a kill uses to avoid a recycled pid, so getting it wrong points an
// enforcement at the wrong process.
func startTicks(pid string) uint64 {
	b, err := os.ReadFile(filepath.Join("/proc", pid, "stat"))
	if err != nil {
		return 0
	}
	s := string(b)
	close := strings.LastIndex(s, ")")
	if close < 0 || close+2 >= len(s) {
		return 0
	}
	// After "pid (comm) " the fields are state(3), ppid(4)... so field 22 is index 19 from here.
	fields := strings.Fields(s[close+1:])
	const startTimeIndex = 19
	if len(fields) <= startTimeIndex {
		return 0
	}
	v, perr := strconv.ParseUint(fields[startTimeIndex], 10, 64)
	if perr != nil {
		return 0
	}
	return v
}

// StartTicksForTest exposes the stat parse so a test can drive it against a process whose name is
// deliberately awkward. Exported for tests only: the behaviour it guards — a comm containing ')' or a
// space shifting every later field — cannot be reached through Attribute without that process also
// holding descriptors under the watched tree, and building a fixture that does both would be testing
// two things at once.
func StartTicksForTest(pid string) uint64 { return startTicks(pid) }
