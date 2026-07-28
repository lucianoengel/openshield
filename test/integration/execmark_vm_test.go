//go:build integration && linux

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// WHICH FANOTIFY MARK DELIVERS AN EXEC EVENT — measured, because this is where D224 was learned.
//
// `execmon` marks the whole MOUNT, with a comment saying it is broader than the named path and that a
// later increment can narrow it. D330 showed what that breadth costs: the agent answers a permission
// event for EVERY exec on the filesystem, and each one blocks the executing process while a readlink
// and a round trip happen. Narrowing it is worth doing, but only against measurement — the reason the
// mount mark is there at all is that a DIRECTORY mark was tried and did not deliver.
//
// This test does not assert a fix. It RECORDS what the kernel does for three mark shapes, so the
// implementation follows evidence rather than a man page:
//
//	1. mount mark                                — the status quo
//	2. directory mark + FAN_EVENT_ON_CHILD       — one mark per directory, covers new files
//	3. per-FILE mark                             — narrowest, needs enumeration and re-marking
//
// It always answers ALLOW immediately, so it can never wedge the machine, and it tears the group down
// on return.

// markProbe opens a fanotify group, applies one mark, and reports which execs produced an event.
type markProbe struct {
	fd     int
	events chan string
	stop   chan struct{}
}

func newMarkProbe(t *testing.T, flags uint, path string) *markProbe {
	t.Helper()
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		t.Skipf("fanotify_init needs CAP_SYS_ADMIN: %v", err)
	}
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|flags, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path); err != nil {
		unix.Close(fd)
		t.Skipf("marking %s with flags %#x: %v", path, flags, err)
	}
	p := &markProbe{fd: fd, events: make(chan string, 64), stop: make(chan struct{})}
	go p.run()
	return p
}

// run reads events and ALLOWS every one immediately. Answering is not optional: an unanswered
// permission event leaves the executing process in TASK_UNINTERRUPTIBLE until the group is closed.
func (p *markProbe) run() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-p.stop:
			return
		default:
		}
		n, err := unix.Read(p.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return
		}
		for off := 0; off+24 <= n; {
			// struct fanotify_event_metadata: len(u32) vers(u8) pad(u8) meta_len(u16) mask(u64) pid(s32) fd(s32)
			evLen := int(uint32(buf[off]) | uint32(buf[off+1])<<8 | uint32(buf[off+2])<<16 | uint32(buf[off+3])<<24)
			if evLen < 24 || off+evLen > n {
				break
			}
			// fd is at offset 16, BEFORE pid — struct fanotify_event_metadata is
			// {event_len, vers, reserved, metadata_len, mask(u64), fd(s32), pid(s32)}. Reading offset 20
			// yields the PID, so the real event fd is never answered and the executing process hangs in
			// TASK_UNINTERRUPTIBLE forever. That is exactly what the first version of this did.
			fd := int32(uint32(buf[off+16]) | uint32(buf[off+17])<<8 | uint32(buf[off+18])<<16 | uint32(buf[off+19])<<24)
			if fd >= 0 {
				path, _ := os.Readlink("/proc/self/fd/" + itoaProbe(int(fd)))
				// ALLOW, always and immediately.
				var resp [8]byte
				putU32(resp[0:], uint32(fd))
				putU32(resp[4:], unix.FAN_ALLOW)
				_, _ = unix.Write(p.fd, resp[:])
				unix.Close(int(fd))
				select {
				case p.events <- path:
				default:
				}
			}
			off += evLen
		}
	}
}

func (p *markProbe) close() { close(p.stop); unix.Close(p.fd) }

// saw reports whether an event for a path arrived within the window.
func (p *markProbe) saw(path string, within time.Duration) bool {
	deadline := time.After(within)
	for {
		select {
		case got := <-p.events:
			if got == path {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func putU32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func itoaProbe(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestWhichFanotifyMarkDeliversAnExecEvent is the measurement the narrowing depends on.
func TestWhichFanotifyMarkDeliversAnExecEvent(t *testing.T) {
	requireRootKernel(t)
	work := t.TempDir()
	dir := filepath.Join(work, "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := execBin(t, dir, "inside-tool")
	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	nested := execBin(t, sub, "nested-tool")

	for _, c := range []struct {
		name  string
		flags uint
		mark  string
	}{
		{"mount mark (status quo)", unix.FAN_MARK_MOUNT, dir},
		{"directory mark + FAN_EVENT_ON_CHILD", unix.FAN_MARK_ONLYDIR, dir}, // ON_CHILD added below
		{"per-FILE mark", 0, inside},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			flags := c.flags
			if c.name == "directory mark + FAN_EVENT_ON_CHILD" {
				flags |= unix.FAN_EVENT_ON_CHILD
			}
			p := newMarkProbe(t, flags, c.mark)
			defer p.close()
			time.Sleep(300 * time.Millisecond)

			_ = exec.Command(inside).Run()
			gotInside := p.saw(inside, 2*time.Second)

			_ = exec.Command(nested).Run()
			gotNested := p.saw(nested, 2*time.Second)

			_ = exec.Command("/bin/true").Run()
			gotOutside := p.saw("/bin/true", 2*time.Second)

			t.Logf("RESULT %-38s direct-child=%-5v nested=%-5v OUTSIDE=%v",
				c.name, gotInside, gotNested, gotOutside)
		})
	}
}
