package canary

import (
	"sort"
	"strings"
)

// PER-PROCESS ATTRIBUTION (HIPS-8).
//
// The detector answers "something is encrypting this tree". That is a true statement and an operator
// cannot act on it. The next question is always the same one — WHICH PROCESS — and until it is answered
// the only available response is to take the whole machine off the network, which is why ransomware
// detection so often ends in a wholesale containment that costs more than the incident.
//
// Attribution here is OPPORTUNISTIC AND HONEST ABOUT IT. When the mass-change fires, the encrypting
// process is usually still running and still walking the tree, so the processes holding descriptors open
// under that directory are the candidates. That is a RACE and it is stated as one: a process that closed
// its descriptors between the write and the scan is invisible, and a process that has the tree open for a
// perfectly good reason is present. This names SUSPECTS, not culprits — the policy decides, and the
// distinction is carried in the confidence rather than smoothed over.
//
// WHAT IT IS NOT. Not a substitute for a kernel hook that reports the writer at write time; that is the
// eBPF/LSM work and this does not pretend to be it. What it is, is the difference between an alert
// nobody can act on and one that names a process with the start-time needed to kill it without hitting a
// recycled pid (HIPS-7).

// Suspect is one process observed holding files open under the watched tree.
type Suspect struct {
	PID int
	// Exe is the resolved executable path, or "" if it could not be read — an empty one is still
	// reported, because "a process we cannot identify has your documents open" is MORE alarming than a
	// named one, not less, and dropping it would remove exactly the case worth escalating.
	Exe string
	// StartTicks is the process start time from /proc/<pid>/stat field 22. With the pid it identifies
	// the specific process INSTANCE, so a kill decided now can revalidate at enforcement time and spare
	// a recycled pid (HIPS-7). 0 = unreadable.
	StartTicks uint64
	// OpenPaths is how many descriptors under the tree this process holds. It is the ranking signal: a
	// process walking a directory encrypting it holds far more than an editor with one file open.
	OpenPaths int
}

// Attribution is the result of one attempt, INCLUDING what it could not see.
//
// Unreadable is not diagnostics. Reading another process's descriptor table needs to be the same user or
// hold CAP_SYS_PTRACE, so an unprivileged agent sees ONLY ITS OWN processes — and would find nothing,
// every time, while reporting a clean result. "No suspects" and "we were not allowed to look" are
// opposite answers to the only question this is asked, and a caller that cannot tell them apart will read
// the reassuring one.
type Attribution struct {
	Suspects []Suspect
	// Scanned is how many processes were examined.
	Scanned int
	// Unreadable is how many existed and could not be examined at all.
	Unreadable int
	// Supported is false where there is no /proc to read. A caller must not read an empty Suspects list
	// as evidence of anything when this is false.
	Supported bool
}

// Blind reports whether this attempt was unable to see enough to be believed: nothing found, and
// something was in the way.
//
// The caller uses it to say "we could not attribute" instead of "nothing was attributable" — the
// difference between an operator who escalates and one who is reassured by a gap.
func (a Attribution) Blind() bool {
	return !a.Supported || (len(a.Suspects) == 0 && a.Unreadable > 0)
}

// rank orders suspects by how many descriptors they hold under the tree, then by pid so the result is
// stable. Stability matters because this ends up in an event id and in an operator's notes; a set that
// reorders between two scans of the same state reads as the situation having changed.
func rank(s []Suspect) []Suspect {
	sort.Slice(s, func(i, j int) bool {
		if s[i].OpenPaths != s[j].OpenPaths {
			return s[i].OpenPaths > s[j].OpenPaths
		}
		return s[i].PID < s[j].PID
	})
	return s
}

// underTree reports whether a resolved descriptor target lies inside dir.
//
// The " (deleted)" suffix the kernel appends is stripped first, and a deleted target still COUNTS —
// ransomware that writes a ciphertext beside the original and unlinks the original is holding exactly
// such a descriptor, so excluding them would blind this to the most common shape of the thing it is
// looking for.
func underTree(target, dir string) bool {
	target = strings.TrimSuffix(target, " (deleted)")
	if target == "" || dir == "" {
		return false
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return strings.HasPrefix(target, dir)
}
