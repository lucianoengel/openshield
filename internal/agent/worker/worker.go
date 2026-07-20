// Package worker is the UNPRIVILEGED half of the agent.
//
// This is where attacker-controlled bytes are read and parsed. It holds no
// elevated capability, and in production it runs with seccomp, no network and
// cgroup limits (T-012 hardens it; the process boundary exists from commit one
// because boundaries are expensive to retrofit).
//
// The precedent for this being mandatory rather than tidy: ClamAV
// CVE-2025-20260, a PDF-parser heap overflow reachable in a privileged daemon.
// AV and EDR content parsers are a repeat-offender RCE vector, and what turns a
// parser memory bug into host compromise is the privilege of the process that
// holds it.
//
// This package MAY import parsers. The privileged package may not — enforced by
// scripts/check-agent-deps.sh.
package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Classifier turns bytes into detector hits. Real detectors arrive in T-007;
// this interface exists now so the process boundary can be built and tested
// against something.
type Classifier interface {
	Classify(ctx context.Context, r io.Reader) ([]*corev1.DetectorHit, error)
}

// Handle serves one ClassifyRequest.
//
// The worker opens the file itself, with its own unprivileged credentials. It
// does NOT receive bytes from the privileged process: that would put
// attacker-controlled content in the privileged address space, which is exactly
// what the split exists to prevent. It also means the worker's access is bounded
// by ordinary filesystem permissions rather than by CAP_SYS_ADMIN.
func Handle(ctx context.Context, c Classifier, req *corev1.ClassifyRequest) *corev1.ClassifyResponse {
	resp := &corev1.ClassifyResponse{
		RequestId: req.GetRequestId(),
		EventId:   req.GetEventId(),
	}

	path := req.GetPath()
	if path == "" {
		// A file handle needs CAP_DAC_READ_SEARCH to resolve (measured in
		// T-005), which the worker deliberately does not have. Resolution is
		// the privileged side's job; it passes a path.
		resp.Error = "worker: no path supplied (handle resolution is not the worker's job)"
		return resp
	}

	f, err := os.Open(path)
	if err != nil {
		// An error is NOT "nothing found". Reporting it as a clean result would
		// let an unreadable or crashing file read as safe.
		resp.Error = fmt.Sprintf("worker: open: %v", err)
		return resp
	}
	defer f.Close()

	max := req.GetMaxBytes()
	if max == 0 {
		max = DefaultMaxBytes
	}
	// Hard ceiling before any parser sees the stream. A decompression bomb must
	// hit a limit rather than exhaust memory (D13).
	lr := &limitReader{R: f, N: int64(max)}

	hits, err := c.Classify(ctx, lr)
	if err != nil {
		resp.Error = fmt.Sprintf("worker: classify: %v", err)
		return resp
	}
	resp.Hits = hits
	resp.Truncated = lr.Truncated
	return resp
}

// DefaultMaxBytes bounds how much of a file the worker will read when the
// request does not say.
const DefaultMaxBytes = 8 << 20 // 8 MiB

// limitReader is io.LimitedReader plus a flag, because silently truncating and
// reporting a clean result is how a large file becomes an evasion technique.
type limitReader struct {
	R         io.Reader
	N         int64
	Truncated bool
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.N <= 0 {
		l.Truncated = true
		return 0, io.EOF
	}
	if int64(len(p)) > l.N {
		p = p[:l.N]
	}
	n, err := l.R.Read(p)
	l.N -= int64(n)
	return n, err
}

// ErrNoClassifier is returned when the worker is started without one.
var ErrNoClassifier = errors.New("worker: no classifier configured")
