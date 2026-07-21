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

	dir := t.TempDir()
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM, unix.AT_FDCWD, dir); err != nil {
		t.Skipf("LOUD SKIP: cannot add FAN_OPEN_PERM mark (need privilege): %v", err)
	}

	target := filepath.Join(dir, "watched.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
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

	// Trigger the permission event. This open blocks until the watchdog answers.
	f, err := os.Open(target)
	if err != nil {
		t.Fatalf("open blocked/failed unexpectedly: %v", err)
	}
	_ = f.Close()

	select {
	case err := <-answered:
		if err != nil {
			t.Fatalf("watchdog failed to answer the real event: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the open was not answered — the kernel edge did not respond")
	}
}

type allowEvaluator struct{}

func (allowEvaluator) Evaluate(context.Context, watchdog.PermissionEvent) (watchdog.Verdict, error) {
	return watchdog.VerdictAllow, nil
}
