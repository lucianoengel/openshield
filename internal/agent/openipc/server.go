package openipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Decide produces the verdict for one file-open question.
//
// A FUNC RETURNING A VERDICT, not an interface returning a Decision, and the reason is the process
// boundary rather than taste. This package is imported by the PRIVILEGED agent for its Client, so
// anything it references is linked into a binary holding CAP_SYS_ADMIN. A `*corev1.Decision` in this
// signature drags protobuf in with it — a wire-format decoder in the privileged process, which is
// exactly what splitting the binaries exists to prevent (D13), and what the build's agent-dependency
// check refuses.
//
// The engine supplies a closure that runs the real pipeline and maps its Decision onto a verdict, in
// the process where corev1 already lives. execipc reached the same shape for the same reason.
type Decide func(ctx context.Context, path string, prefix []byte) (Verdict, error)

// Server is the UNPRIVILEGED side: it answers file-open questions from the privileged gate.
//
// It SERVES verdicts; it never asks for them. The direction matters — the privileged process decodes
// only this server's fixed-width response frame, so a compromised engine cannot hand the agent a
// length to allocate on (see the package doc).
type Server struct {
	Decide Decide
	// Logf, not a *slog.Logger, and for the same reason Decide is a func returning a Verdict: this
	// package is imported by the PRIVILEGED agent, and log/slog pulls in encoding/json — a parser in a
	// process holding CAP_SYS_ADMIN, which the build's agent-dependency check refuses (D13). execipc
	// reached this shape first; the reason was not obvious until the check said so.
	Logf    func(format string, a ...any)
	Timeout time.Duration

	mu sync.Mutex
	ln net.Listener
}

// DefaultServeTimeout bounds one exchange. It sits inside the client's timeout, which sits inside the
// watchdog's budget: a server still working past it is producing an answer nobody can use, because the
// kernel has already been told to allow.
const DefaultServeTimeout = 120 * time.Millisecond

// Listen binds the socket, replacing a stale one left by a previous run.
//
// A LEFTOVER SOCKET FILE IS NOT A REASON TO REFUSE TO START. The engine restarting into a path its
// predecessor left behind is ordinary, and failing there would mean the gate stays down after every
// unclean shutdown — with the agent then failing open on every event, which is exactly the state this
// exists to avoid.
func (s *Server) Listen(ctx context.Context, path string) error {
	if s.Decide == nil {
		return errors.New("openipc: no decider — a server that answered without deciding would be a " +
			"gate that allows everything while reporting itself active")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	// 0600: the socket answers a question the PRIVILEGED gate asks, and anything that can connect can
	// learn which paths are being opened on this host.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			if ctx.Err() != nil {
				return nil
			}
			// One failed accept must not stop the gate: the agent would then fail open on every
			// subsequent event, silently, for the life of the process.
			s.logf("openipc: accept failed: %v", aerr)
			continue
		}
		go s.handle(ctx, conn)
	}
}

// handle answers requests on one connection until it closes.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultServeTimeout
	}
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(timeout * 4)) // generous: the client owns the real bound
		req, err := ReadRequest(conn)
		if err != nil {
			// A malformed frame ends the CONNECTION, not the server. Continuing on a stream whose
			// framing is in doubt would answer the wrong questions, and the client reconnects.
			return
		}

		dctx, cancel := context.WithTimeout(ctx, timeout)
		verdict, derr := s.Decide(dctx, req.Path, req.Prefix)
		cancel()

		if derr != nil {
			// ALLOW on error, and say so. The client would fail open anyway on a missing answer; an
			// explicit allow is faster and leaves the reason here, where it can be read.
			verdict = VerdictAllow
			s.logf("openipc: deciding failed for %s — allowing: %v", req.Path, derr)
		}
		if werr := WriteResponse(conn, Response{ID: req.ID, Verdict: verdict}); werr != nil {
			return
		}
	}
}

func (s *Server) logf(format string, a ...any) {
	if s.Logf != nil {
		s.Logf(format, a...)
	}
}
