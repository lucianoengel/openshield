//go:build linux

package openmon

import (
	"context"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// metaLen is the fixed size of struct fanotify_event_metadata in FAN_CLASS_CONTENT mode.
const metaLen = 24

// Monitor holds the fanotify descriptor and the directories it marked.
type Monitor struct {
	fd          int
	watched     []string
	maxInFlight int
}

// SetMaxInFlight bounds how many permission events are answered concurrently. Zero uses the default.
func (m *Monitor) SetMaxInFlight(n int) { m.maxInFlight = n }

// Open marks each directory for file-open permission events.
//
// FAN_CLASS_CONTENT gives a permission channel with real descriptors — the responder answers on them,
// and the evaluator reads its bounded prefix from them rather than re-opening the path (which would
// deadlock the host and be a TOCTOU hole besides). NONBLOCK so the read loop can honour context.
//
// FAN_EVENT_ON_CHILD is what makes a DIRECTORY mark deliver opens of the files inside it. Without it an
// inode mark reports only opens of the directory itself, which is not what an operator naming a
// directory means — and the failure would be silent: the gate would run, report itself active, and see
// almost nothing.
func Open(paths []string) (*Monitor, error) {
	if len(paths) == 0 {
		return nil, ErrNoPaths
	}
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
		unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("openmon: fanotify_init (needs CAP_SYS_ADMIN and a permission-capable "+
			"kernel): %w", err)
	}
	m := &Monitor{fd: fd, watched: append([]string(nil), paths...)}
	for _, p := range paths {
		// A DIRECTORY is required. Marking a regular file would work, but naming one is almost always a
		// mistake an operator meant as "this directory", and the difference is invisible afterwards.
		st, serr := os.Stat(p)
		if serr != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("openmon: %s: %w", p, serr)
		}
		if !st.IsDir() {
			unix.Close(fd)
			return nil, fmt.Errorf("openmon: %s is not a directory — the open gate marks directories, "+
				"and a file mark would silently cover only that one file", p)
		}
		if err := unix.FanotifyMark(fd,
			unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, p); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("openmon: marking %s: %w", p, err)
		}
	}
	return m, nil
}

// NotifyFD is the fanotify descriptor the responder writes its answer to. The watchdog owns answering;
// this exposes the channel it answers on.
func (m *Monitor) NotifyFD() int { return m.fd }

// Close releases the fanotify descriptor, which drops every mark with it.
func (m *Monitor) Close() error { return unix.Close(m.fd) }

// Watched reports the directories this monitor marked, so a caller can say what is covered at startup
// rather than leaving an operator to infer it.
func (m *Monitor) Watched() []string { return append([]string(nil), m.watched...) }

// Run reads permission events until ctx is done, handing each to the watchdog.
//
// EVERY EVENT IS ANSWERED EXACTLY ONCE and its descriptor released, whatever the verdict. A leaked
// descriptor is a slow death for the agent; an unanswered event is a process blocked forever.
func (m *Monitor) Run(ctx context.Context, wd *watchdog.Watchdog) error {
	n := m.maxInFlight
	if n <= 0 {
		n = DefaultMaxInFlight
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	// Outstanding answers are waited for on the way out, so a shutdown does not leave a process blocked
	// in a permission window with nothing left to answer it.
	defer wg.Wait()

	buf := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := unix.Read(m.fd, buf)
		if err != nil {
			switch err {
			case unix.EAGAIN: // EWOULDBLOCK is the same errno on Linux
				if werr := waitReadable(ctx, m.fd); werr != nil {
					return werr
				}
				continue
			case unix.EINTR:
				continue
			default:
				return fmt.Errorf("openmon: read: %w", err)
			}
		}
		rest := buf[:n]
		for len(rest) >= metaLen {
			md, next, ok := decodeMeta(rest)
			if !ok {
				// A malformed or short trailing record. There is nothing safely answerable here, and
				// guessing would mean answering an event that may not exist.
				break
			}
			rest = next
			if md.FD < 0 {
				continue // a kernel overflow marker: no descriptor, nothing to answer
			}
			// HANDLED CONCURRENTLY, bounded. Answering one at a time makes the watchdog's per-event
			// budget meaningless under load: it starts when the event is DEQUEUED, not when the kernel
			// blocked the process, so the Nth opener waits N × the decision cost while every answer
			// still reads as inside budget. Measured on a live kernel — twelve concurrent opens at 25ms
			// each took 306ms, exactly serial.
			//
			// The exec gate has the same loop and does not need this: an exec decision is ~41µs, so
			// fifty concurrent execs queue for 2ms. An open decision is ~6ms, so fifty queue for 300ms.
			// The same structure is safe at one scale and not at the other.
			//
			// BOUNDED, because unbounded goroutines in a process holding CAP_SYS_ADMIN is what an
			// attacker opening ten thousand files at once would cost. When every slot is busy the
			// producer BLOCKS here, which is backpressure: the kernel's queue absorbs it, and an event
			// that waits too long is answered by the watchdog's budget as a fail-open, which is the
			// correct answer for a gate that cannot keep up.
			fd := md.FD
			pid := md.PID
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				// readlink INSIDE the goroutine, before the fd is closed: it is best-effort audit data,
				// and doing it on the read loop would put a /proc lookup in front of every event.
				_ = wd.Handle(ctx, watchdog.PermissionEvent{PID: pid, FD: fd, Path: readlinkFD(fd)})
				unix.Close(int(fd))
			}()
		}
	}
}

// decodeMeta decodes one fanotify_event_metadata. A short buffer or a length that runs past it is
// malformed: ok is false and the caller stops rather than over-reading.
//
// struct fanotify_event_metadata { __u32 event_len; __u8 vers; __u8 reserved;
// __u16 metadata_len; __aligned_u64 mask; __s32 fd; __s32 pid; }
func decodeMeta(buf []byte) (m meta, rest []byte, ok bool) {
	if len(buf) < metaLen {
		return meta{}, buf, false
	}
	m.EventLen = uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
	m.Vers = buf[4]
	m.FD = int32(uint32(buf[16]) | uint32(buf[17])<<8 | uint32(buf[18])<<16 | uint32(buf[19])<<24)
	m.PID = int32(uint32(buf[20]) | uint32(buf[21])<<8 | uint32(buf[22])<<16 | uint32(buf[23])<<24)
	if m.EventLen < metaLen || int(m.EventLen) > len(buf) {
		return m, nil, false
	}
	return m, buf[m.EventLen:], true
}

type meta struct {
	EventLen uint32
	Vers     uint8
	FD       int32
	PID      int32
}

// readlinkFD resolves the event descriptor to a path, best-effort and for audit only. A failure is an
// empty string, never an error that would stop the gate answering.
func readlinkFD(fd int32) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	return p
}

// waitReadable blocks until the descriptor is readable or ctx is done, with a short poll timeout so
// cancellation is observed promptly rather than at the next event.
func waitReadable(ctx context.Context, fd int) error {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := unix.Poll(fds, 200)
		if err != nil && err != unix.EINTR {
			return fmt.Errorf("openmon: poll: %w", err)
		}
		if n > 0 {
			return nil
		}
	}
}
