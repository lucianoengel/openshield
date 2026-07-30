package printguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Server answers print-verdict requests. It runs in the ENGINE (unprivileged), which classifies the job in
// the sandboxed worker and applies the policy.
type Server struct {
	// Decide classifies a job and returns its verdict. An error means the engine could not decide, and the
	// connection is dropped so the filter sees a failure and FAILS OPEN — an evaluation failure must never
	// be laundered into an "allow" that looks like a decision.
	Decide func(ctx context.Context, req Request) (Verdict, error)
	// ReadTimeout guards an abandoned connection.
	ReadTimeout time.Duration
	// Logf is optional.
	Logf func(format string, a ...any)

	// mu guards addr. Listen runs in its own goroutine — that is the only way to use it, since it blocks
	// until ctx is done — so ANY caller that then asks where it bound is reading across a goroutine
	// boundary. The obvious spelling, a plain `listener net.Listener` field read by Addr, was a data race
	// on two counts: the unsynchronised field itself, and `net.UnixListener.Addr()` racing with the
	// `Close()` that the ctx watcher performs. Storing the resolved address once, under a lock, removes
	// both — Addr never touches the listener.
	mu   sync.RWMutex
	addr string
}

// Listen serves until ctx is cancelled. A stale socket file is removed first, so a restart after an unclean
// shutdown does not silently lose print control for the life of the process.
func (s *Server) Listen(ctx context.Context, socket string) error {
	if s.Decide == nil {
		return errors.New("printguard: server needs a Decide func")
	}
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("printguard: removing stale socket: %w", err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("printguard: listen %s: %w", socket, err)
	}
	// The CUPS filter runs as the spooler's user (commonly `lp`), not as the engine's user, so the socket
	// must be group/other-reachable. 0666 on a unix socket in a directory the deployer controls is the
	// pragmatic choice; the blast radius of reaching it is "can ask for a print verdict", not privilege.
	if err := os.Chmod(socket, 0o666); err != nil {
		_ = ln.Close()
		return fmt.Errorf("printguard: chmod %s: %w", socket, err)
	}
	s.mu.Lock()
	s.addr = ln.Addr().String()
	s.mu.Unlock()
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("printguard: accept: %w", err)
		}
		go s.handle(ctx, conn)
	}
}

// Addr reports the bound socket path, or "" before Listen has bound one.
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addr
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	t := s.ReadTimeout
	if t <= 0 {
		t = 60 * time.Second // a large job takes a while to stream
	}
	if err := conn.SetDeadline(time.Now().Add(t)); err != nil {
		return
	}
	req, err := ReadRequest(conn)
	if err != nil {
		if s.Logf != nil && ctx.Err() == nil {
			s.Logf("print-verdict: dropping connection: %v", err)
		}
		return
	}
	v, derr := s.Decide(ctx, req)
	if derr != nil {
		// Drop rather than answer: the filter fails open on a read error, and an "allow" here would be
		// indistinguishable from a real decision to allow.
		if s.Logf != nil {
			s.Logf("print-verdict: evaluation failed for job on %q: %v", req.Printer, derr)
		}
		return
	}
	_ = WriteResponse(conn, Response{ID: req.ID, Verdict: v})
}
