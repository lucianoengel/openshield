//go:build linux

package fanotify

import (
	"context"
	"errors"
	"fmt"

	"time"

	"golang.org/x/sys/unix"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// ErrUnsupported is returned by Open on a platform without fanotify.
var ErrUnsupported = errors.New("fanotify: not supported on this platform")

// Watcher observes a directory in notify mode.
type Watcher struct {
	dir string
	fd  int
}

// Open inits fanotify in NOTIFY mode with DFID_NAME reporting and marks dir. This
// works UNPRIVILEGED (probed) — unlike permission mode, which needs init-namespace
// CAP_SYS_ADMIN.
func Open(dir string) (*Watcher, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_REPORT_DFID_NAME, unix.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("fanotify init: %w", err)
	}
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD,
		unix.FAN_CREATE|unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE, unix.AT_FDCWD, dir); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("fanotify mark %s: %w", dir, err)
	}
	return &Watcher{dir: dir, fd: fd}, nil
}

// Next blocks until a file event arrives (or ctx is done) and returns it. Records
// without a filename are skipped. The path is watchedDir/name — no privileged
// handle resolution.
func (w *Watcher) Next(ctx context.Context) (*corev1.Event, error) {
	buf := make([]byte, 8192)
	for {
		if err := waitReadable(ctx, w.fd); err != nil {
			return nil, err
		}
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			return nil, fmt.Errorf("fanotify read: %w", err)
		}
		off := 0
		for off < n {
			ev, consumed, ok := ParseEvent(w.dir, buf[off:n])
			if !ok || consumed == 0 {
				break
			}
			off += consumed
			if ev.GetFilesystem().GetResolvedPath() != "" {
				return ev, nil
			}
		}
	}
}

// waitReadable polls the fd, honouring the context deadline.
func waitReadable(ctx context.Context, fd int) error {
	timeoutMs := -1
	if dl, ok := ctx.Deadline(); ok {
		ms := int(time.Until(dl).Milliseconds())
		if ms <= 0 {
			return context.DeadlineExceeded
		}
		timeoutMs = ms
	}
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		nn, err := unix.Poll(pfd, timeoutMs)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if nn == 0 {
			return context.DeadlineExceeded
		}
		return nil
	}
}

// Close releases the fanotify fd.
func (w *Watcher) Close() error { return unix.Close(w.fd) }
