//go:build linux

package execmon

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// Monitor is a running fanotify exec-permission group.
type Monitor struct {
	fd int // the fanotify group fd
}

// Open creates a fanotify group in permission-content mode and marks FAN_OPEN_EXEC_PERM
// on each watched path, so an exec of a binary under a watched path raises a permission
// event this monitor answers. It needs CAP_SYS_ADMIN (privileged). At least one path is
// required; a bad path aborts (a mis-configured monitor must not run watching nothing).
func Open(paths []string) (*Monitor, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("execmon: no paths to watch")
	}
	// FAN_CLASS_CONTENT gives a permission channel with real fds (what the responder
	// answers on); NONBLOCK so the read loop can honor context between events.
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("execmon: fanotify_init (need CAP_SYS_ADMIN + a permission-capable kernel): %w", err)
	}
	// Mark the MOUNT each path lives on (FAN_MARK_MOUNT). A plain directory (inode) mark
	// does NOT deliver FAN_OPEN_EXEC_PERM for files executed WITHIN the directory — exec
	// events are on the file, so a mount mark is required to catch execs under a path.
	// This is broader than the named path (the whole mount); a later increment can narrow
	// with per-file marks or path filtering.
	for _, p := range paths {
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, p); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("execmon: marking mount for %s: %w", p, err)
		}
	}
	return &Monitor{fd: fd}, nil
}

// NotifyFD is the fanotify group fd the FanotifyResponder writes answers to.
func (m *Monitor) NotifyFD() int { return m.fd }

// Close releases the fanotify group.
func (m *Monitor) Close() error { return unix.Close(m.fd) }

// Run reads exec-permission events and drives the watchdog to answer each, until ctx is
// done. For every event: decode it, build a PermissionEvent (pid + the accessed fd + the
// binary path via /proc/self/fd), let the watchdog answer ALLOW/DENY (under its budget +
// self-PID exemption + fail-open), then CLOSE the event fd (else an fd leak).
//
// Robustness is safety: the executing process is parked uninterruptibly awaiting an
// answer, so a decode error or a short read must STILL answer the kernel (allow) and never
// hang. An undecodable buffer is dropped (nothing to answer — no fd was handed out).
func (m *Monitor) Run(ctx context.Context, wd *watchdog.Watchdog) error {
	buf := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := unix.Read(m.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				// Non-blocking: no event ready. Wait briefly for readability, honoring ctx.
				if werr := waitReadable(ctx, m.fd); werr != nil {
					return werr
				}
				continue
			}
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("execmon: read: %w", err)
		}
		rest := buf[:n]
		for len(rest) >= metaLen {
			md, next, ok := decodeMeta(rest)
			if !ok {
				break // a malformed/short trailing record: nothing safely answerable
			}
			rest = next
			// A metadata-only record with no fd (kernel overflow marker) carries FD < 0;
			// there is nothing to answer or close.
			if md.FD < 0 {
				continue
			}
			e := watchdog.PermissionEvent{PID: md.PID, FD: md.FD, Path: readlinkFD(md.FD)}
			// The watchdog always answers the kernel exactly once (allow/deny/fail-open).
			_ = wd.Handle(ctx, e)
			// Release the event fd regardless of the answer — else a leak per exec.
			unix.Close(int(md.FD))
		}
	}
}

// waitReadable blocks until the fanotify fd is readable or ctx is done, using a poll with
// a short timeout so cancellation is observed promptly.
func waitReadable(ctx context.Context, fd int) error {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := unix.Poll(fds, 100) // 100ms, then re-check ctx
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n > 0 {
			return nil
		}
	}
}

// readlinkFD resolves the accessed file's path from its fd (best-effort, for audit and the
// deny-list match). An unresolvable fd yields "" — the evaluator then cannot match a path
// and allows (the deny-list is a positive control, so an unknown path is not blocked).
func readlinkFD(fd int32) string {
	p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fd)))
	if err != nil {
		return ""
	}
	return p
}
