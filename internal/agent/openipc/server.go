package openipc

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Decider produces a Decision from a path and a content prefix the caller already holds.
//
// Satisfied by prefilter.Decider.DecideBytes — the same classify-in-the-worker and evaluate-the-policy
// machinery the async engine runs, on a bounded prefix and without an audit write.
type Decider interface {
	DecideBytes(ctx context.Context, path string, prefix []byte) (*corev1.Decision, error)
}

// Server is the UNPRIVILEGED side: it answers file-open questions from the privileged gate.
//
// It SERVES verdicts; it never asks for them. The direction matters — the privileged process decodes
// only this server's fixed-width response frame, so a compromised engine cannot hand the agent a
// length to allocate on (see the package doc).
type Server struct {
	Decide  Decider
	Logger  *slog.Logger
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
			s.log().Warn("openipc: accept failed", slog.String("err", aerr.Error()))
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
		dec, derr := s.Decide.DecideBytes(dctx, req.Path, req.Prefix)
		cancel()

		verdict := VerdictAllow
		switch {
		case derr != nil:
			// ALLOW on error, and say so. The client would fail open anyway on a missing answer; an
			// explicit allow is faster and leaves the reason here, where it can be read.
			s.log().Warn("openipc: deciding failed — allowing", slog.String("path", req.Path),
				slog.String("err", derr.Error()))
		case dec.GetAction() == corev1.Action_ACTION_BLOCK,
			dec.GetAction() == corev1.Action_ACTION_QUARANTINE_LOCAL:
			// Only an action that MEANS refuse becomes a deny. The mapping is explicit rather than
			// "anything that is not ALLOW", so a new action added to the closed set does not silently
			// become a reason to block an open.
			verdict = VerdictDeny
		}
		if werr := WriteResponse(conn, Response{ID: req.ID, Verdict: verdict}); werr != nil {
			return
		}
	}
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
