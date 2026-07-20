// Command openshield-worker is the UNPRIVILEGED parser process.
//
// It reads ClassifyRequests on stdin, opens the named file with its own
// credentials, classifies, and writes ClassifyResponses on stdout. It holds no
// elevated capability and, in production, no network access.
//
// A separate binary from openshield-agent by design: one binary with a --worker
// flag would carry the parsers in its dependency graph regardless of which path
// ran, and the import check that keeps the privileged side clean would be
// meaningless.
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/ipc"
	"github.com/lucianoengel/openshield/internal/agent/worker"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// nullClassifier finds nothing. Real detectors arrive in T-007; this exists so
// the process boundary can be exercised end to end now.
type nullClassifier struct{}

func (nullClassifier) Classify(context.Context, io.Reader) ([]*corev1.DetectorHit, error) {
	return nil, nil
}

func main() {
	c := worker.Classifier(nullClassifier{})
	in, out := os.Stdin, os.Stdout

	for {
		var req corev1.ClassifyRequest
		if err := ipc.ReadFrame(in, &req); err != nil {
			if errors.Is(err, io.EOF) {
				return // parent closed the pipe: ordinary shutdown
			}
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp := worker.Handle(ctx, c, &req)
		cancel()
		if err := ipc.WriteFrame(out, resp); err != nil {
			return
		}
	}
}
