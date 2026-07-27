//go:build linux

package watchdog_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// This exercises the REAL kernel edge: a FAN_OPEN_PERM mark, an open that blocks
// in the kernel until answered, and the watchdog answering through the
// FanotifyResponder. It needs CAP_SYS_ADMIN and a kernel with fanotify
// permission events, so it SKIPS LOUDLY when it cannot run — a skipped
// privileged test that shows green must not be mistaken for a passing one.
func TestFanotifyPermissionAnsweredForReal(t *testing.T) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		t.Skipf("LOUD SKIP: fanotify permission mode unavailable (need CAP_SYS_ADMIN): %v\n"+
			"The kernel answer path is NOT verified by this run; only the watchdog logic is.", err)
	}
	defer unix.Close(fd)

	// THE FILE IS CREATED FIRST AND THE MARK GOES ON THE FILE, not on its directory (D316).
	//
	// This test was written at T-011 and, until it was finally run on real hardware, marked `t.TempDir()`
	// — and a plain DIRECTORY inode mark does not deliver permission events for files opened WITHIN that
	// directory. It delivers them for opens of the DIRECTORY ITSELF. So the triggering open produced no
	// event, nothing was ever read, and the test timed out. It could only ever have failed; it had simply
	// never run, because it skips without CAP_SYS_ADMIN and the build host deliberately has none.
	//
	// This is the SAME kernel fact D224 paid for in `execmon`, where a directory mark silently let a
	// denied binary execute, and the fix there was FAN_MARK_MOUNT. A mount mark is wrong HERE: the mount
	// is /tmp, so it would deliver every other process's opens on the whole tmpfs, and this test answers
	// and CLOSES the fd of whatever it reads — it would interfere with unrelated processes and be flaky
	// in exactly the way a privileged test must not be. Marking the one file is precise and sufficient.
	target := filepath.Join(t.TempDir(), "watched.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM, unix.AT_FDCWD, target); err != nil {
		t.Skipf("LOUD SKIP: cannot add FAN_OPEN_PERM mark (need privilege): %v", err)
	}

	// Reader loop: decode one permission event and hand it to the watchdog.
	answered := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		n, err := unix.Read(fd, buf)
		if err != nil {
			answered <- fmt.Errorf("read fanotify: %w", err)
			return
		}
		metaSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
		if n < metaSize {
			answered <- fmt.Errorf("short event: %d bytes", n)
			return
		}
		meta := *(*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[0]))
		w := &watchdog.Watchdog{
			SelfPID:   int32(os.Getpid()),
			Budget:    time.Second,
			Responder: watchdog.FanotifyResponder{NotifyFD: fd},
			Evaluator: allowEvaluator{},
		}
		err = w.Handle(context.Background(), watchdog.PermissionEvent{
			PID: meta.Pid, FD: meta.Fd,
		})
		if meta.Fd >= 0 {
			_ = unix.Close(int(meta.Fd))
		}
		answered <- err
	}()

	// THE TRIGGERING OPEN RUNS IN ITS OWN GOROUTINE, so an unanswered event fails this test with a
	// diagnosis instead of hanging it (D316).
	//
	// The open BLOCKS IN THE KERNEL until something answers, and this process is both the trigger and the
	// responder. Opening on the main goroutine therefore meant that a responder which never answered
	// blocked before the select below could fire: the failure surfaced as Go's test-timeout panic, tens of
	// seconds later, naming nothing. Verified by mutation — deleting the response write produced exactly
	// that. Off the main goroutine, the select wins and says what went wrong.
	opened := make(chan error, 1)
	go func() {
		f, err := os.Open(target)
		if err == nil {
			_ = f.Close()
		}
		opened <- err
	}()

	select {
	case err := <-answered:
		if err != nil {
			t.Fatalf("watchdog failed to answer the real event: %v", err)
		}
		// The blocked open must now COMPLETE. An answer the kernel did not act on would leave the caller
		// stuck, which is the outcome the fail-open contract exists to prevent (D17): a watchdog that
		// reports success while the process it was gating never resumes has hung the machine, not
		// protected it.
		select {
		case err := <-opened:
			if err != nil {
				t.Errorf("the open failed after an ALLOW verdict: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the watchdog answered ALLOW and the open never returned — the caller is still " +
				"blocked in the kernel, which is an outage rather than an enforcement")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the open was not answered — the kernel edge did not respond. If the mark was placed on " +
			"a DIRECTORY, this is the expected outcome and not a product fault: a directory inode mark " +
			"delivers permission events for opens OF THE DIRECTORY, not for files opened inside it")
	}
}

type allowEvaluator struct{}

func (allowEvaluator) Evaluate(context.Context, watchdog.PermissionEvent) (watchdog.Verdict, error) {
	return watchdog.VerdictAllow, nil
}
