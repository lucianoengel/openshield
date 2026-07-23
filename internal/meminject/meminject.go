// Package meminject detects code injection (HIPS-4) by scanning a process's memory map for
// writable-AND-executable regions — the W^X-violation signature of injected shellcode. Legitimate code
// is mapped read-execute from a file; injected code lives in a writable page that is also executable.
//
// It reads ONLY the memory-map METADATA (address ranges + permissions) and the process's executable
// path — never the process's memory contents (OpenShield does not dump memory; that would need
// process_vm_readv, which the worker sandbox denies). A scan across processes skips any it cannot read,
// so an unprivileged scan covers its own processes and a root scan covers the whole fleet.
package meminject

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Region is one memory mapping from /proc/<pid>/maps.
type Region struct {
	Start uint64
	End   uint64
	Perms string // e.g. "r-xp", "rw-p", "rwxp"
	Path  string // the backing file, or "" for an anonymous mapping
}

// isWX reports whether perms grant BOTH write and execute — the injected-code signature. A region that
// is executable but not writable (normal code) or writable but not executable (normal data) is not W+X.
func isWX(perms string) bool {
	return strings.Contains(perms, "w") && strings.Contains(perms, "x")
}

// parseMaps decodes /proc/<pid>/maps lines. A malformed line is skipped, not fatal.
func parseMaps(r io.Reader) []Region {
	var out []Region
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		// address           perms offset  dev   inode      pathname
		// 55e0-55e1 r-xp 00000000 08:01 1234 /usr/bin/foo
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		dash := strings.IndexByte(fields[0], '-')
		if dash < 0 {
			continue
		}
		start, err1 := strconv.ParseUint(fields[0][:dash], 16, 64)
		end, err2 := strconv.ParseUint(fields[0][dash+1:], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		path := ""
		if len(fields) >= 6 {
			path = strings.Join(fields[5:], " ")
		}
		out = append(out, Region{Start: start, End: end, Perms: fields[1], Path: path})
	}
	return out
}

// SuspectRegions returns the writable-and-executable regions (the injection signal).
func SuspectRegions(regions []Region) []Region {
	var out []Region
	for _, r := range regions {
		if isWX(r.Perms) {
			out = append(out, r)
		}
	}
	return out
}

// ScanPID reads <procRoot>/<pid>/maps and returns its suspect (W+X) regions.
func ScanPID(procRoot string, pid int) ([]Region, error) {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "maps"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return SuspectRegions(parseMaps(f)), nil
}

// ExePath returns the process's executable path (readlink <procRoot>/<pid>/exe), or "" best-effort.
func ExePath(procRoot string, pid int) string {
	p, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return p
}

// ScanAll scans every process under procRoot and returns the pids with suspect regions. A process whose
// maps cannot be read (a different user's without privilege, or one that exited) is skipped and counted
// in unreadable — so an unprivileged run covers its own processes and a root run covers the whole fleet.
func ScanAll(procRoot string) (suspects map[int][]Region, unreadable int) {
	suspects = map[int][]Region{}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return suspects, 0
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid directory
		}
		regions, err := ScanPID(procRoot, pid)
		if err != nil {
			unreadable++
			continue
		}
		if len(regions) > 0 {
			suspects[pid] = regions
		}
	}
	return suspects, unreadable
}
