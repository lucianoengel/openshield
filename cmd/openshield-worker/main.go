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
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/ipc"
	"github.com/lucianoengel/openshield/internal/agent/sandbox"
	"github.com/lucianoengel/openshield/internal/agent/worker"
	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func main() {
	// Harden BEFORE reading any attacker-controlled input (T-012). The seccomp
	// filter denies the network syscalls, so a parser RCE — the threat the
	// privilege split exists for — cannot phone home. A filter that could not be
	// applied is not a sandbox: on Linux any error other than "unsupported" is
	// fatal; off Linux (dev only, D9) it is a LOUD warning, never a silent pass.
	if err := sandbox.Apply(); err != nil {
		if errors.Is(err, sandbox.ErrUnsupported) {
			fmt.Fprintln(os.Stderr, "openshield-worker: WARNING — SANDBOX NOT APPLIED "+
				"(seccomp unsupported on this platform); do not treat this run as hardened")
		} else {
			fmt.Fprintf(os.Stderr, "openshield-worker: refusing to parse without a sandbox: %v\n", err)
			os.Exit(1)
		}
	}

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
