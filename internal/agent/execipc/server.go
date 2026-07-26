package execipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// Server is the UNPRIVILEGED side: it answers exec-verdict requests from the privileged gate by running
// the pipeline (HIPS-3 increment 2a).
//
// It lives in this package rather than in the engine so both halves of the protocol are written and tested
// together — a wire format whose two ends live apart is a wire format whose ends drift. Nothing here is
// imported by the privileged binary: it is the Client that the agent holds, and the server side is only
// reachable from the engine, which may use corev1/OPA freely.
type Server struct {
	// Evaluate produces the verdict for one request. Production passes an execguard-backed evaluator, so
	// the DENY_EXEC-only semantics live in ONE place (execguard.ExecEvaluator) rather than being
	// re-derived here where they could drift.
	Evaluate func(ctx context.Context, e watchdog.PermissionEvent) (watchdog.Verdict, error)
	// ReadTimeout bounds how long a connection may sit idle mid-frame, so a stuck or malicious client
	// cannot pin a goroutine forever.
	ReadTimeout time.Duration
	// Logf is optional; nil discards.
	Logf func(format string, a ...any)

	mu       sync.Mutex
	listener net.Listener
}

// DefaultReadTimeout is generous relative to the client's per-request timeout: the client gives up long
// before this, so this is only a guard against an abandoned connection, not part of the decision path.
const DefaultReadTimeout = 30 * time.Second

// Listen binds the unix socket and serves until ctx is cancelled.
//
// A STALE SOCKET FILE is removed before binding. Without that, an engine restart after an unclean shutdown
// fails with "address already in use" and the exec gate silently loses its verdict source for the life of
// the process — the kind of operational papercut that turns an enforcement feature off without anyone
// noticing.
func (s *Server) Listen(ctx context.Context, socket string) error {
	if s.Evaluate == nil {
		return errors.New("execipc: server needs an Evaluate func")
	}
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("execipc: removing stale socket %s: %w", socket, err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("execipc: listen %s: %w", socket, err)
	}
	// Filesystem permissions are the access control on this socket. It is restricted to the owner: the
	// engine and the privileged agent run as the same user or the deployer arranges access deliberately.
	// The blast radius of reaching it is "can ask for exec verdicts", not privilege — but a world-writable
	// verdict socket would still let any local process probe policy, so it is 0600.
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("execipc: chmod %s: %w", socket, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // shutting down
			}
			return fmt.Errorf("execipc: accept: %w", err)
		}
		go s.handle(ctx, conn)
	}
}

// Addr returns the bound socket path, once Listen has bound it (for tests).
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// handle serves one connection: a stream of request/response pairs, in order.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	timeout := s.ReadTimeout
	if timeout <= 0 {
		timeout = DefaultReadTimeout
	}
	for {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return
		}
		req, err := ReadRequest(conn)
		if err != nil {
			// A malformed frame ends the connection. The client redials, and — critically — it treats the
			// dropped connection as an error, so the exec fails OPEN rather than waiting on a stream that
			// will not answer.
			if s.Logf != nil && ctx.Err() == nil {
				s.Logf("exec-verdict server: dropping connection: %v", err)
			}
			return
		}
		verdict, err := s.Evaluate(ctx, watchdog.PermissionEvent{PID: req.PID, Path: req.Path, FD: -1})
		if err != nil {
			// A pipeline error is NOT answered with a permissive verdict: the connection drops, the client
			// sees a read error, and the watchdog fails open with a loud audit. Sending "allow" here would
			// launder an evaluation failure into a decision, and nothing downstream could tell them apart.
			if s.Logf != nil {
				s.Logf("exec-verdict server: evaluation failed for pid %d (%s): %v", req.PID, req.Path, err)
			}
			return
		}
		v := VerdictAllow
		if verdict == watchdog.VerdictBlock {
			v = VerdictDeny
		}
		if err := WriteResponse(conn, Response{ID: req.ID, Verdict: v}); err != nil {
			return
		}
	}
}
