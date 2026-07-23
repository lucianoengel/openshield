//go:build linux

package main

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/sys/unix"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/fim"
)

// fimWatchMask is the real-time watch event mask on the watched directories' children:
//   - FAN_MODIFY | FAN_CLOSE_WRITE — a content change (and a create-with-content, which fires CLOSE_WRITE).
//   - FAN_DELETE | FAN_MOVED_FROM — a child DELETED from / moved OUT of a watched dir (the "remove the
//     evidence" tamper). These are directory-entry events reported against the marked directory; delivered
//     in the unprivileged FID mode (FAN_REPORT_DFID_NAME) this watch uses — proven on the VM.
//
// FAN_MOVED_TO / FAN_CREATE (an ADD) are deliberately left to the poll: an added file is a weaker tamper
// signal. Every event here is only a TRIGGER — fim.Scan re-diffs the cryptographic baseline to decide what
// actually drifted, so a timestomped edit is still caught and a no-content change yields nothing.
const fimWatchMask = unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_DELETE | unix.FAN_MOVED_FROM | unix.FAN_EVENT_ON_CHILD

// fimWatchSource is the REAL-TIME FIM producer (HIPS-4 increment 2): it watches the critical paths'
// directories with unprivileged fanotify and, on a change, triggers an IMMEDIATE baseline re-check — so
// tamper is caught in ~milliseconds rather than up to one poll interval late. The fanotify event is ONLY
// the trigger; the drift is computed by fim.Scan (so a timestomped edit is caught, a no-content change
// yields nothing). Additive to the poll (which stays the completeness backstop). Best-effort: a
// directory whose mark cannot be added is logged and skipped (fail-to-wire), never fatal.
//
// It marks directories with FAN_EVENT_ON_CHILD so a MODIFICATION of a file INSIDE a watched directory is
// reported (a plain dir mark reports child creates but not child-content modifies — the main tamper
// case). It uses plain NOTIF class (no FID): the event is used only as a trigger, so its contents are
// not parsed — fim.Scan determines what actually drifted.
func fimWatchSource(ctx context.Context, m *fim.Manifest, paths []string, opts fim.Options, debounce time.Duration, events chan<- *corev1.Event, log *slog.Logger) {
	// FID (DFID_NAME) reporting is REQUIRED for an UNPRIVILEGED watch (D52): the non-FID class needs
	// CAP_SYS_ADMIN. The events carry a directory FID + name, but this watch does not parse them — an
	// event is only a trigger, and fim.Scan determines what drifted.
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_REPORT_DFID_NAME, unix.O_RDONLY)
	if err != nil {
		log.Warn("fim: real-time watch unavailable (fanotify init) — running poll-only", slog.String("err", err.Error()))
		return
	}
	defer unix.Close(fd)

	marked := 0
	for _, d := range fimWatchDirs(paths) {
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, fimWatchMask, unix.AT_FDCWD, d); err != nil {
			log.Warn("fim: real-time watch could not mark a directory — poll still covers it", slog.String("dir", d), slog.String("err", err.Error()))
			continue
		}
		marked++
	}
	if marked == 0 {
		log.Warn("fim: real-time watch marked no directories — running poll-only")
		return
	}
	log.Info("fim: real-time watch active", slog.Int("dirs", marked), slog.Duration("debounce", debounce))

	trigger := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			if ctx.Err() != nil {
				return
			}
			n, err := unix.Read(fd, buf)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					if werr := waitReadableFD(ctx, fd); werr != nil {
						return
					}
					continue
				}
				if err == unix.EINTR {
					continue
				}
				return
			}
			if n > 0 {
				select {
				case trigger <- struct{}{}: // coalesce: a pending trigger already covers this event
				default:
				}
			}
		}
	}()

	runFimTriggerLoop(ctx, m, paths, opts, debounce, trigger, events, log)
}

// waitReadableFD blocks until fd is readable or ctx is done, polling with a short timeout so
// cancellation is observed promptly.
func waitReadableFD(ctx context.Context, fd int) error {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := unix.Poll(fds, 100)
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
