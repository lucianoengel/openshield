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
	"os"
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
	// CONTEXT CANCELLATION CLOSES STDIN RATHER THAN SIGKILLING, which is what CommandContext does by
	// default — and that default silently pre-empted Close's graceful path entirely. On shutdown the
	// context is cancelled first, so the parser was killed mid-work no matter how politely Close asked.
	//
	// The worker's shutdown signal IS end-of-stdin: its loop returns on EOF. So cancellation closes the
	// pipe and WaitDelay bounds how long a worker that ignores it may hold shutdown open, after which the
	// runtime kills it. Same guarantee as before, reached the right way round.
	//
	// This is also what made the worker invisible to coverage — a SIGKILLed process flushes no profile, so
	// the parse path the entire privilege split exists for measured 0%. That was recorded as "unmeasurable"
	// when it was really "we kill it too fast".
	// THE WORKER'S STDERR GOES NOWHERE UNLESS IT IS WIRED, and it was not.
	//
	// exec.Cmd defaults an unset Stderr to /dev/null, so every message this binary has ever printed —
	// twenty-nine of them, including "DLP indexes loaded UNVERIFIED", "content signatures active" and
	// the NIPS-11 rule refusals — was written to nothing. The code that prints them says they are
	// "warned about at load"; nobody was ever warned. It is the observability defect this project has
	// found four times in counters, in the one process that cannot be reached any other way: the worker
	// has no port, no ledger and no bus, so its stderr is its ONLY channel.
	//
	// Inheriting is safe by construction: the worker deliberately never prints content (D10/D29), and a
	// test asserts its output carries none.
	cmd.Stderr = os.Stderr

	cmd.Cancel = func() error { return in.Close() }
	cmd.WaitDelay = closeGrace
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

// closeGrace is how long a worker is given to exit on its own after its stdin closes. Short, because this
// runs on the shutdown path and an agent that takes seconds to stop is one an operator learns to SIGKILL.
const closeGrace = 2 * time.Second

// Close stops the worker: close its stdin, let it exit, and kill it only if it does not.
//
// IT USED TO CLOSE STDIN AND KILL IMMEDIATELY, which is wrong twice.
//
// A parser killed mid-work leaves whatever it was holding — a decompression scratch file, a partially
// written temp — and this is the process whose whole job is opening attacker-supplied archives. Giving it
// the moment it needs to unwind is ordinary hygiene, and the grace is bounded so a wedged worker still dies.
//
// And it made the worker UNMEASURABLE: a SIGKILLed process flushes no coverage profile, so
// internal/agent/worker read 0% while cmd/openshield-worker read 48% — the parse path the entire privilege
// split exists for was invisible to the coverage run. That was recorded as "unmeasurable" and it was
// really "we kill it too fast", which is a different thing and a fixable one.
//
// The kill is kept for the case that matters: a worker that ignores EOF must not hold shutdown open.
func (w *Worker) Close() error {
	var err error
	w.once.Do(func() {
		_ = w.in.Close()
		if w.cmd.Process == nil {
			_ = w.cmd.Wait()
			return
		}
		done := make(chan error, 1)
		go func() { done <- w.cmd.Wait() }()
		select {
		case <-done:
			// Exited on EOF, as a well-behaved worker does.
		case <-time.After(closeGrace):
			_ = w.cmd.Process.Kill()
			<-done
		}
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
