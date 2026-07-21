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
	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func main() {
	// The real pattern classifier (T-007). It lives in the worker's dependency
	// graph, which MAY hold parsers; the privileged binary's may not, and
	// scripts/check-agent-deps.sh enforces that split.
	c := worker.Classifier(classify.New())
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
