package openipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// THE GATE FAILS OPEN ON EVERYTHING (D17/D18).
//
// These are the tests that matter most in this package. A file-open gate that failed closed would hang
// every process on the host — every path below must therefore ALLOW, and must return the error so the
// watchdog can audit WHY. "The gate allowed everything" and "the gate allowed everything because the
// engine was down" are the same event to a user and different ones to an operator.

func tempFileFD(t *testing.T, body string) int32 {
	t.Helper()
	path := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return int32(f.Fd())
}

// TestAnUnreachableEngineAllows.
func TestAnUnreachableEngineAllows(t *testing.T) {
	c := &Client{SocketPath: filepath.Join(t.TempDir(), "absent.sock"), Timeout: 50 * time.Millisecond}
	v, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, FD: tempFileFD(t, "data")})
	if v != watchdog.VerdictAllow {
		t.Errorf("an unreachable engine produced %v — a file-open gate that fails closed hangs every "+
			"process on the host", v)
	}
	if err == nil {
		t.Error("the fail-open was silent; the watchdog cannot audit a reason it was not given")
	}
}

// serveOnce answers one request with the given verdict byte, or with raw bytes when supplied.
func serveOnce(t *testing.T, verdict Verdict, raw []byte) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "gate.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		req, rerr := ReadRequest(conn)
		if rerr != nil {
			return
		}
		if raw != nil {
			_, _ = conn.Write(raw)
			return
		}
		_ = WriteResponse(conn, Response{ID: req.ID, Verdict: verdict})
	}()
	return sock
}

// TestADenyVerdictBlocks — without this, every assertion above is satisfied by a client that always
// allows, which is a gate that does nothing.
func TestADenyVerdictBlocks(t *testing.T) {
	c := &Client{SocketPath: serveOnce(t, VerdictDeny, nil), Timeout: time.Second}
	v, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, FD: tempFileFD(t, "secret")})
	if err != nil {
		t.Fatalf("a well-formed DENY errored: %v", err)
	}
	if v != watchdog.VerdictBlock {
		t.Errorf("got %v, want VerdictBlock — the gate cannot refuse anything", v)
	}
}

func TestAnAllowVerdictAllows(t *testing.T) {
	c := &Client{SocketPath: serveOnce(t, VerdictAllow, nil), Timeout: time.Second}
	v, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, FD: tempFileFD(t, "ok")})
	if err != nil || v != watchdog.VerdictAllow {
		t.Errorf("got %v, %v; want VerdictAllow, nil", v, err)
	}
}

// TestAMismatchedResponseIdAllowsAndDropsTheConnection.
//
// An answer to a DIFFERENT question means the connection is desynchronised, and the next answer would
// be too. A gate reading one answer behind is worse than one that fails open: it would refuse files
// nobody asked about and release the ones it was asked about.
func TestAMismatchedResponseIdAllowsAndDropsTheConnection(t *testing.T) {
	var buf []byte
	{
		var b netBuf
		if err := WriteResponse(&b, Response{ID: 999999, Verdict: VerdictDeny}); err != nil {
			t.Fatal(err)
		}
		buf = b.b
	}
	c := &Client{SocketPath: serveOnce(t, 0, buf), Timeout: time.Second}
	v, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, FD: tempFileFD(t, "x")})
	if v != watchdog.VerdictAllow {
		t.Errorf("a mismatched response id produced %v, want Allow", v)
	}
	if !errors.Is(err, ErrIDMismatch) {
		t.Errorf("got %v, want ErrIDMismatch", err)
	}
}

// TestAnUnreadableDescriptorAllows: no content means no basis for a verdict, and the gate exists to
// catch content. A file it cannot read is not a file it should refuse.
func TestAnUnreadableDescriptorAllows(t *testing.T) {
	c := &Client{SocketPath: serveOnce(t, VerdictDeny, nil), Timeout: time.Second}
	v, _ := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, FD: 1 << 20})
	if v != watchdog.VerdictAllow {
		t.Errorf("an unreadable descriptor produced %v, want Allow", v)
	}
}

// TestAnEmptyFileIsCarriedNotFailed: an empty file has no content to match and must still get a real
// verdict rather than a fail-open, or every truncate-then-write would slip past unexamined.
func TestAnEmptyFileIsCarriedNotFailed(t *testing.T) {
	c := &Client{SocketPath: serveOnce(t, VerdictAllow, nil), Timeout: time.Second}
	v, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, FD: tempFileFD(t, "")})
	if err != nil {
		t.Errorf("an empty file failed open with %v; it should have been asked about normally", err)
	}
	if v != watchdog.VerdictAllow {
		t.Errorf("got %v", v)
	}
}

// netBuf is a tiny io.Writer for building a raw frame.
type netBuf struct{ b []byte }

func (n *netBuf) Write(p []byte) (int, error) { n.b = append(n.b, p...); return len(p), nil }
