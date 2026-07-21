package sandbox_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/sandbox"
)

// A bomb must be stopped AT the guard, before the caller receives the
// over-limit bytes — not discovered by the process running out of memory.
func TestBombHitsGuard(t *testing.T) {
	// inputSize 0 DISABLES the ratio bound, so this test isolates the ABSOLUTE
	// cap — otherwise the ratio check would catch the bomb and a regression that
	// broke the absolute cap would pass unnoticed. The stream is endless zeros.
	endless := &zeroReader{}
	g := sandbox.NewDecompressGuard(endless, 0)

	// Run the copy under a bounded wait. The guard MUST stop the endless stream
	// with ErrBomb; if it does not, this fails FAST (a clean assertion) rather
	// than hanging the whole suite on the test-binary timeout — a guard whose
	// removal is only caught by a 10-minute hang is a poor guard.
	type res struct {
		n   int64
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := io.Copy(io.Discard, g)
		ch <- res{n, err}
	}()
	select {
	case r := <-ch:
		if !errors.Is(r.err, sandbox.ErrBomb) {
			t.Fatalf("err = %v, want ErrBomb after %d bytes — a bomb must hit the guard, not memory", r.err, r.n)
		}
		if r.n > sandbox.DefaultMaxExpanded {
			t.Errorf("guard delivered %d bytes, past the %d cap", r.n, sandbox.DefaultMaxExpanded)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the guard did not stop an endless stream — the absolute cap is not enforced")
	}
}

// The ratio bound catches a small input claiming a huge expansion even under the
// absolute cap.
func TestRatioBoundRejects(t *testing.T) {
	// 10-byte input; at 200:1 the ratio cap is 2000 bytes. Feed 5000.
	src := bytes.NewReader(bytes.Repeat([]byte("A"), 5000))
	g := sandbox.NewDecompressGuard(src, 10)
	_, err := io.Copy(io.Discard, g)
	if !errors.Is(err, sandbox.ErrBomb) {
		t.Fatalf("err = %v, want ErrBomb — 5000 bytes from a 10-byte input is 500:1", err)
	}
}

// A legitimate, modestly-compressible stream passes through untouched.
func TestLegitimateStreamPasses(t *testing.T) {
	body := strings.Repeat("real content ", 100) // ~1300 bytes
	g := sandbox.NewDecompressGuard(strings.NewReader(body), 100)
	got, err := io.ReadAll(g)
	if err != nil {
		t.Fatalf("legitimate stream rejected: %v", err)
	}
	if string(got) != body {
		t.Error("guard altered a legitimate stream")
	}
}

// Nesting beyond the depth cap is rejected rather than recursed.
func TestNestingDepthRejected(t *testing.T) {
	d := sandbox.NewDepthTracker()
	var err error
	for i := 0; i <= sandbox.DefaultMaxDepth+1; i++ {
		if err = d.EnterArchive(); err != nil {
			break
		}
	}
	if !errors.Is(err, sandbox.ErrBomb) {
		t.Fatalf("err = %v, want ErrBomb once depth exceeds %d", err, sandbox.DefaultMaxDepth)
	}
}

// LeaveArchive lets a balanced traversal stay under the cap indefinitely.
func TestBalancedNestingIsFine(t *testing.T) {
	d := sandbox.NewDepthTracker()
	for i := 0; i < 1000; i++ {
		if err := d.EnterArchive(); err != nil {
			t.Fatalf("balanced traversal wrongly rejected at iteration %d: %v", i, err)
		}
		d.LeaveArchive()
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
