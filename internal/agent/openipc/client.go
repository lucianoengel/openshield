package openipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// Client is the PRIVILEGED side: a watchdog.Evaluator that answers a file-open permission event by
// asking the unprivileged engine, over a socket, using bytes it read from the kernel's descriptor.
//
// IT FAILS OPEN ON EVERYTHING. An unreachable engine, a timeout, a truncated frame, a verdict byte
// this build does not recognise — every one returns Allow with an error, and the watchdog audits the
// fail-open at high severity (D17/D18). A file-open gate that failed closed would hang every process
// on the host, which is a far worse outcome than the disclosure it exists to make harder (D16).
//
// The error is RETURNED rather than swallowed, so the watchdog records WHY it failed open. "The gate
// allowed everything for six hours" and "the gate allowed everything for six hours because the engine
// was down" are the same event to a user and different ones to an operator.
type Client struct {
	// SocketPath is the engine's open-gate socket. Distinct from the exec gate's, so the two are
	// independently enable-able: an operator may reasonably want exec prevention without file-open
	// prevention, whose availability cost is much higher.
	SocketPath string
	// Timeout bounds the whole round trip. It must sit INSIDE the watchdog's budget — the watchdog
	// answers the kernel when its budget elapses, and a client still waiting at that point is doing
	// work whose answer can no longer be used.
	Timeout time.Duration
	// MaxPrefix bounds the bytes read from the event descriptor. Capped at MaxPrefixLen regardless.
	MaxPrefix int

	seq atomic.Uint64

	mu   sync.Mutex
	conn net.Conn
}

// DefaultTimeout leaves room inside the watchdog's budget for the read, the round trip, and the answer.
const DefaultTimeout = 150 * time.Millisecond

// Evaluate answers one permission event.
func (c *Client) Evaluate(ctx context.Context, e watchdog.PermissionEvent) (watchdog.Verdict, error) {
	prefix, rerr := c.readPrefix(e.FD)
	if rerr != nil {
		// A file that cannot be read is not a file that should be blocked: the gate exists to catch
		// content, and no content means no basis for a verdict. Fail open, loudly.
		return watchdog.VerdictAllow, fmt.Errorf("openipc: reading the event descriptor: %w", rerr)
	}

	req := Request{ID: c.seq.Add(1), PID: e.PID, Path: e.Path, Prefix: prefix}
	resp, err := c.roundTrip(ctx, req)
	if err != nil {
		return watchdog.VerdictAllow, err
	}
	if resp.ID != req.ID {
		// The connection is desynchronised: this answer belongs to a different question, and the next
		// one would too. Drop it so the following event starts clean rather than reading answers one
		// behind — a gate answering the previous file's question is worse than one that fails open.
		c.dropConn()
		return watchdog.VerdictAllow, ErrIDMismatch
	}
	if resp.Verdict == VerdictDeny {
		return watchdog.VerdictBlock, nil
	}
	return watchdog.VerdictAllow, nil
}

// readPrefix reads a bounded head of the file from the descriptor the KERNEL supplied.
//
// PREAD FROM ZERO, not Read: the descriptor's offset is not this code's to assume, and a verdict that
// depended on where some other read left it would be silently position-dependent.
//
// It does NOT re-open the path. Re-opening would raise a second permission event that this same gate
// must answer — a deadlock inside an uninterruptible window — and would be a TOCTOU hole, since the
// path may name a different file by then.
func (c *Client) readPrefix(fd int32) ([]byte, error) {
	if fd < 0 {
		return nil, nil
	}
	n := c.MaxPrefix
	if n <= 0 || n > MaxPrefixLen {
		n = MaxPrefixLen
	}
	buf := make([]byte, n)
	f := os.NewFile(uintptr(fd), "fanotify-event")
	// NOT closed: the descriptor belongs to the producer's loop, which releases it after the answer.
	// Closing it here would release it twice and could close an unrelated descriptor by the time the
	// number is reused.
	got, err := f.ReadAt(buf, 0)
	if err != nil && got == 0 {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, nil // an empty file is not an error; it is a file with nothing to match
		}
		return nil, err
	}
	return buf[:got], nil
}

// roundTrip sends one request and reads its answer, reconnecting once if the connection was closed
// underneath us — an engine restart should cost one fail-open, not every subsequent event.
func (c *Client) roundTrip(ctx context.Context, req Request) (Response, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.dial()
		if err != nil {
			return Response{}, fmt.Errorf("openipc: dialing the engine: %w", err)
		}
		_ = conn.SetDeadline(deadline)
		if err := WriteRequest(conn, req); err != nil {
			c.dropConn()
			if attempt == 0 {
				continue
			}
			return Response{}, fmt.Errorf("openipc: sending: %w", err)
		}
		resp, err := ReadResponse(conn)
		if err != nil {
			c.dropConn()
			if attempt == 0 {
				continue
			}
			return Response{}, fmt.Errorf("openipc: reading the verdict: %w", err)
		}
		return resp, nil
	}
	return Response{}, fmt.Errorf("openipc: no answer after a reconnect")
}

func (c *Client) dial() (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	conn, err := net.DialTimeout("unix", c.SocketPath, DefaultTimeout)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return conn, nil
}

func (c *Client) dropConn() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// Close releases the connection.
func (c *Client) Close() error {
	c.dropConn()
	return nil
}
