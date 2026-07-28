//go:build linux

package execmon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// Monitor is a running fanotify exec-permission group.
type Monitor struct {
	fd      int // the fanotify group fd
	mode    MarkMode
	marked  int
	watched []string
}

// Open creates a fanotify group in permission-content mode and marks FAN_OPEN_EXEC_PERM,
// so an exec of a watched binary raises a permission event this monitor answers. It needs
// CAP_SYS_ADMIN (privileged). At least one path is required; a bad path aborts (a
// mis-configured monitor must not run watching nothing).
//
// Equivalent to OpenWithMode(paths, MarkMount) — the broad, always-correct choice.
func Open(paths []string) (*Monitor, error) { return OpenWithMode(paths, MarkMount) }

// OpenWithMode chooses the mark's breadth, which must match the gate's SEMANTICS (D331).
//
// The two modes fail in opposite directions and the asymmetry is the whole design: a mount mark can only
// WASTE (an event, and a blocked process, for every exec on the mount — including ones the gate does not
// police), while per-file marks can only MISS (anything not marked produces no event, and under
// default-deny an unseen exec RUNS). In a security control those are not symmetric, so narrowness is
// used only where the scope is already defined and defended.
//
// MEASURED on kernel 6.8, because the mount mark exists precisely because a narrower one was tried and
// did not deliver (D224): a mount mark delivers for direct children, nested children and nothing on
// other mounts; a per-file mark delivers only for the file itself; and a DIRECTORY mark with
// FAN_EVENT_ON_CHILD is refused outright with EINVAL. That last one would have been the best answer —
// one mark per directory, new files covered by the kernel — and it is not available.
func OpenWithMode(paths []string, mode MarkMode) (*Monitor, error) {
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
	m := &Monitor{fd: fd, mode: mode, watched: append([]string(nil), paths...)}
	if mode == MarkPerFile {
		if err := m.markExecutables(paths); err != nil {
			unix.Close(fd)
			return nil, err
		}
		return m, nil
	}
	for _, p := range paths {
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, p); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("execmon: marking mount for %s: %w", p, err)
		}
	}
	return m, nil
}

// MarkFile adds a per-file mark, used both for the initial walk and for binaries that appear later.
// An unmarkable file is an ERROR to the caller rather than a silent skip: under default-deny an unmarked
// binary produces no event and therefore RUNS, so a skipped mark is a bypass, not a missed optimisation.
func (m *Monitor) MarkFile(path string) error {
	if err := unix.FanotifyMark(m.fd, unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path); err != nil {
		return fmt.Errorf("execmon: marking file %s: %w", path, err)
	}
	return nil
}

// markExecutables walks each watched path and marks every regular file with an execute bit.
//
// It walks rather than reading one level, because a per-file mark does NOT cover a nested directory
// (measured) — so a tree walk is what makes "the monitored directory" mean the directory and everything
// under it, which is what an operator naming a directory means.
func (m *Monitor) markExecutables(paths []string) error {
	marked := 0
	for _, root := range paths {
		err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				return nil
			}
			if err := m.MarkFile(p); err != nil {
				return err
			}
			marked++
			return nil
		})
		if err != nil {
			return fmt.Errorf("execmon: walking %s: %w", root, err)
		}
	}
	m.marked = marked
	return nil
}

// Marked reports how many files carry a per-file mark, so a caller can say so at startup rather than
// leaving an operator to guess what is covered.
func (m *Monitor) Marked() int { return m.marked }

// Watched returns the directories this monitor was pointed at.
func (m *Monitor) Watched() []string { return m.watched }

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
