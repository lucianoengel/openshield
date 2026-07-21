package privileged

import (
	"context"
	"sync"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Pool is a set of worker processes classified across concurrently. A single
// Worker serializes on a mutex (one framed request at a time), which is correct
// for the endpoint engine (one event at a time) but a bottleneck for the
// concurrent gateway proxy. The Pool exposes the SAME Classify signature as a
// Worker, so it is a drop-in for the classifier interface; internally it fans
// requests across N workers, each still its own seccomp/no-network sandbox
// (D29/D35).
type Pool struct {
	ctx  context.Context
	path string
	args []string

	idle chan *Worker

	mu     sync.Mutex
	closed bool
}

// StartPool launches size worker processes (min 1). On any spawn failure it closes
// what it started and returns the error.
func StartPool(ctx context.Context, workerPath string, size int, args ...string) (*Pool, error) {
	if size < 1 {
		size = 1
	}
	p := &Pool{ctx: ctx, path: workerPath, args: args, idle: make(chan *Worker, size)}
	for i := 0; i < size; i++ {
		w, err := StartWorker(ctx, workerPath, args...)
		if err != nil {
			p.Close()
			return nil, err
		}
		p.idle <- w
	}
	return p, nil
}

// Classify acquires an idle worker (blocking with backpressure when all are busy,
// and honouring ctx cancellation), classifies, and releases it. On ANY error the
// worker's framed-IPC state is unknown (a timeout desyncs the protocol, a crash
// kills it), so it is discarded and replaced — a poisoned worker never serves a
// later request. The error is returned regardless (D17: a worker error is
// surfaced, never a clean result).
func (p *Pool) Classify(ctx context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	var w *Worker
	select {
	case w = <-p.idle:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	resp, err := w.Classify(ctx, req)
	if err != nil {
		p.release(p.replace(w))
		return resp, err
	}
	p.release(w)
	return resp, nil
}

// replace discards a worker whose IPC state is unknown and returns a fresh one; if
// the spawn fails, the old (closed) handle is returned so the slot is not lost
// (its next use errors and retries) rather than shrinking the pool toward deadlock.
func (p *Pool) replace(dead *Worker) *Worker {
	dead.Close()
	nw, err := StartWorker(p.ctx, p.path, p.args...)
	if err != nil {
		return dead
	}
	return nw
}

// release returns a worker to the idle set. If the pool is closed, the worker is
// closed instead of parked.
func (p *Pool) release(w *Worker) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		w.Close()
		return
	}
	p.idle <- w
}

// Close drains and closes the idle workers. In-flight workers exit with the
// process; a subsequent release closes rather than parks (see release). Idempotent.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	for {
		select {
		case w := <-p.idle:
			w.Close()
		default:
			return nil
		}
	}
}
