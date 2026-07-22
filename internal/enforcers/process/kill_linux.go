//go:build linux

package process

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// platformKill terminates a process by pid using a PIDFD (HIPS-7): pidfd_open refers to the SPECIFIC
// process instance, and pidfd_send_signal targets that instance — so if the process exited between
// the decision and the kill and its pid was RECYCLED, the signal returns ESRCH and does NOT kill the
// new (possibly critical) holder of the reused pid. A plain kill(pid) would kill whatever now holds
// the number. A process that is already gone (pidfd_open → ESRCH) needs no kill.
func platformKill(pid int) error {
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
