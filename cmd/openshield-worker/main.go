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
	"crypto/ed25519"
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
	// scripts/check-agent-deps.sh enforces that split. HON-1: it also loads
	// operator-authored SIGNED custom rules (D100) when configured — otherwise that
	// feature was unreachable in production.
	cls := loadClassifier()
	// DLP-3 exact-data matching: when a serialized EDM index is configured, add its
	// detector so the worker matches actual sensitive values, not only formats. The
	// index is k-anonymized (hashes only), so shipping it into the sandbox never
	// carries the raw dataset (ADR-9). A malformed index aborts — a silently-missing
	// EDM detector would read as "no exact-data leaks" when none were checked.
	if ep := os.Getenv("OPENSHIELD_EDM_INDEX"); ep != "" {
		blob, err := os.ReadFile(ep)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openshield-worker: reading EDM index %q: %v\n", ep, err)
			os.Exit(1)
		}
		idx, err := classify.LoadEDMIndex(blob)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openshield-worker: bad EDM index %q: %v\n", ep, err)
			os.Exit(1)
		}
		cls.AddEDM(idx)
		fmt.Fprintf(os.Stderr, "openshield-worker: DLP-3 EDM active (%d fingerprints)\n", idx.Size())
	}
	c := worker.Classifier(cls)
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

// loadClassifier builds the pattern classifier and, when configured, merges operator-
// authored SIGNED custom rules (HON-1, D100). The bundle path is OPENSHIELD_RULES_BUNDLE and
// the trusted operator public key is OPENSHIELD_RULES_PUBKEY. Loading is FAIL-CLOSED on the
// RULES — a missing key, an unreadable/tampered/unsigned bundle loads NO custom rules (the
// worker still runs with the built-in detectors, so classification availability is
// preserved) — never silently trusting unverified rules. A loud message records the outcome.
func loadClassifier() *classify.Classifier {
	base := classify.New()
	bundlePath := os.Getenv("OPENSHIELD_RULES_BUNDLE")
	if bundlePath == "" {
		return base
	}
	pubPath := os.Getenv("OPENSHIELD_RULES_PUBKEY")
	if pubPath == "" {
		fmt.Fprintln(os.Stderr, "openshield-worker: OPENSHIELD_RULES_BUNDLE set but OPENSHIELD_RULES_PUBKEY unset — refusing unverified rules, using built-ins only (HON-1)")
		return base
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "openshield-worker: bad rules public key %q (%v) — using built-ins only\n", pubPath, err)
		return base
	}
	signed, err := os.ReadFile(bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshield-worker: reading rules bundle %q: %v — using built-ins only\n", bundlePath, err)
		return base
	}
	rules, err := classify.LoadSignedRules(signed, ed25519.PublicKey(pub))
	if err != nil {
		// Fail-closed: a bundle that does not verify loads NOTHING (D100), but the worker
		// still classifies with the built-ins rather than refusing to start.
		fmt.Fprintf(os.Stderr, "openshield-worker: rules bundle rejected (%v) — using built-ins only (HON-1)\n", err)
		return base
	}
	fmt.Fprintf(os.Stderr, "openshield-worker: loaded %d signed custom rule(s) (HON-1)\n", len(rules))
	return base.WithRules(rules)
}
