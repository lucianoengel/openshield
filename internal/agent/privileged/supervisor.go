// Package privileged is the PRIVILEGED half of the agent.
//
// It holds CAP_SYS_ADMIN, sets up fanotify marks, and answers permission events
// while a real process sits blocked in TASK_UNINTERRUPTIBLE. Everything here is
// bookkeeping: path handling, IPC framing, deadlines.
//
// This package MUST NOT parse attacker-controlled bytes, and must not even hold
// them. Enforced by scripts/check-agent-deps.sh, which fails the build if the
// privileged binary's dependency graph contains encoding/*, compress/*,
// archive/* or any document parser.
//
// The two halves are separate BINARIES, not one binary with a flag. A single
// binary would have the parsers in its dependency graph regardless of which
// code path ran, and the import check — the only mechanism that keeps this
// boundary real rather than aspirational — would be meaningless.
package privileged

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/ipc"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

var (
	ErrWorkerUnavailable = errors.New("privileged: parser worker unavailable")
	ErrWorkerTimeout     = errors.New("privileged: parser worker exceeded deadline")
)

// Worker is a handle to the unprivileged parser process.
type Worker struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  io.ReadCloser
	mu   sync.Mutex // one request in flight; the protocol is synchronous
	once sync.Once
}

// StartWorker launches the unprivileged worker binary.
//
// In production systemd runs the worker under its own unprivileged user with
// seccomp and cgroup limits (T-012). Spawning it here keeps the dev path
// identical in shape to the deployed one, so the boundary is exercised rather
// than simulated.
func StartWorker(ctx context.Context, workerPath string, args ...string) (*Worker, error) {
	cmd := exec.CommandContext(ctx, workerPath, args...)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWorkerUnavailable, err)
	}
	return &Worker{cmd: cmd, in: in, out: out}, nil
}

// Classify sends one request and waits for the matching response.
//
// The deadline is enforced here, on the privileged side, because the worker is
// the less trusted party and a request that never returns would stall the
// pipeline — and behind it, a blocked process. A worker that hangs must look
// exactly like a worker that failed.
func (w *Worker) Classify(ctx context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := ipc.WriteFrame(w.in, req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWorkerUnavailable, err)
	}

	type result struct {
		resp *corev1.ClassifyResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		var resp corev1.ClassifyResponse
		err := ipc.ReadFrame(w.out, &resp)
		done <- result{&resp, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return nil, fmt.Errorf("%w: %v", ErrWorkerUnavailable, r.err)
		}
		// A response for a different request means the stream has desynchronised.
		// Accepting it would attribute one file's findings to another — quietly
		// wrong in exactly the way that matters for an audit trail.
		if r.resp.GetRequestId() != req.GetRequestId() {
			return nil, fmt.Errorf("%w: response id %q != request id %q",
				ErrWorkerUnavailable, r.resp.GetRequestId(), req.GetRequestId())
		}
		return r.resp, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %v", ErrWorkerTimeout, ctx.Err())
	}
}

// Close stops the worker.
func (w *Worker) Close() error {
	var err error
	w.once.Do(func() {
		_ = w.in.Close()
		if w.cmd.Process != nil {
			_ = w.cmd.Process.Kill()
		}
		_ = w.cmd.Wait()
	})
	return err
}

// Wait reports when the worker exits, so its death is observable rather than
// discovered on the next request.
func (w *Worker) Wait(d time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- w.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		return nil
	}
}
