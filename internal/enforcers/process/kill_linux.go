//go:build linux

package process

import (
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// platformKill terminates a process by pid, REVALIDATING the observation-time identity (HIPS-7).
// pidfd_open(pid) alone is NOT reuse-safe: it resolves the pid to whatever process holds it NOW, so a
// pidfd opened at kill time gives no protection if the original exited and the pid was recycled. So
// when a captured start-time is supplied, this re-reads the current pid's start-time and kills only on
// a match; a mismatch means the pid was reused, so it is a no-op (the new holder is spared). With no
// captured identity (startTicks==0) it falls back to a best-effort pidfd kill. pidfd_send_signal on a
// since-exited process still returns ESRCH (a no-op), and an already-gone pid needs no kill.
func platformKill(pid int, startTicks uint64) error {
	if startTicks != 0 {
		if cur := readStartTicksLinux(pid); cur != startTicks {
			// The pid holds a different process instance now (recycled), or is gone — do NOT kill it.
			return nil
		}
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		if err == unix.ESRCH {
			return nil // already gone — nothing to kill (not an error)
		}
		return err
	}
	defer unix.Close(fd)
	return unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
}

// readStartTicksLinux reads field 22 (starttime, clock ticks) of /proc/<pid>/stat — the process
// instance identity used to resist pid reuse. 0 on any error (gone/unreadable). comm (field 2) may
// contain spaces/parens, so fields are parsed after the LAST ')': starttime is index 19 there.
func readStartTicksLinux(pid int) uint64 {
	b, err := os.ReadFile("/proc/" + itoa(pid) + "/stat")
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

// procIdentityOf reads a process's TRUSTED identity for the critical-process guard (HIPS-8): its real
// executable via /proc/<pid>/exe (the kernel's record of the actual binary — a process can change its
// comm/argv[0] but not make this point at a different file without exec'ing it), plus that binary's
// ownership. A read error means the process is gone or unreadable.
func procIdentityOf(pid int) (ProcIdentity, error) {
	exe, err := os.Readlink("/proc/" + itoa(pid) + "/exe")
	if err != nil {
		return ProcIdentity{}, err
	}
	// Stat the real binary (follow the link) for its ownership and permissions.
	fi, err := os.Stat(exe)
	if err != nil {
		return ProcIdentity{}, err
	}
	id := ProcIdentity{ExePath: exe, OtherWritable: fi.Mode().Perm()&0o022 != 0}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		id.RootOwned = st.Uid == 0
	}
	return id, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
