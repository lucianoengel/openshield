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
	"sync/atomic"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/ipc"
	"github.com/lucianoengel/openshield/internal/agent/sandbox"
	"github.com/lucianoengel/openshield/internal/agent/worker"
	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/signature"
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
	// DLP-3 / ADR-9: when an operator index public key is configured, every index shipped into the
	// sandbox MUST be operator-SIGNED and verify against it before loading — a poisoned or swapped
	// index cannot silently disable (or overwhelm) exfil detection. Without the key, the legacy
	// unsigned load is preserved but warned about (opt-in-closed per deployment, like signed rules).
	indexPub := loadIndexPubKey()
	if ep := os.Getenv("OPENSHIELD_EDM_INDEX"); ep != "" {
		blob := loadIndexBytes(ep, classify.IndexKindEDM, indexPub)
		idx, err := classify.LoadEDMIndex(blob)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openshield-worker: bad EDM index %q: %v\n", ep, err)
			os.Exit(1)
		}
		cls.AddEDM(idx)
		fmt.Fprintf(os.Stderr, "openshield-worker: DLP-3 EDM active (%d fingerprints)\n", idx.Size())
	}
	// DLP-3 multi-cell EDM: a record index fires only when several cells of the SAME
	// record co-occur — far lower false-positive than single-value. Also
	// k-anonymized (hashes only), safe to ship into the sandbox. Malformed aborts.
	if rp := os.Getenv("OPENSHIELD_EDM_RECORD_INDEX"); rp != "" {
		blob := loadIndexBytes(rp, classify.IndexKindRecord, indexPub)
		ridx, err := classify.LoadRecordIndex(blob)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openshield-worker: bad EDM record index %q: %v\n", rp, err)
			os.Exit(1)
		}
		cls.AddRecordEDM(ridx)
		fmt.Fprintf(os.Stderr, "openshield-worker: DLP-3 multi-cell EDM active (%d records)\n", ridx.Size())
	}
	// DLP-3 IDM: a document-fingerprint index fires when content contains a
	// substantial portion of a sensitive document (excerpt/reformat tolerant).
	// k-anonymized (shingle hashes only), safe to ship into the sandbox. Malformed aborts.
	if dp := os.Getenv("OPENSHIELD_IDM_INDEX"); dp != "" {
		blob := loadIndexBytes(dp, classify.IndexKindIDM, indexPub)
		didx, err := classify.LoadDocumentIndex(blob)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openshield-worker: bad IDM index %q: %v\n", dp, err)
			os.Exit(1)
		}
		cls.AddIDM(didx)
		fmt.Fprintf(os.Stderr, "openshield-worker: DLP-3 IDM active (%d documents)\n", didx.Size())
	}
	c := worker.Classifier(cls)

	// NIPS-2 content-signature engine: when a ruleset is configured, the worker matches
	// operator signatures over each flow body (here, behind the sandbox, because the body
	// is attacker content — D72) and reports content-free ThreatMatches. A malformed
	// ruleset aborts (a silently-missing signature engine would read as "no network
	// threats" when none were checked, the EDM-index discipline). It hot-reloads: the
	// watcher swaps the ruleset atomically so a new signature takes effect with no restart.
	var rules atomic.Pointer[signature.Ruleset]
	if rp := os.Getenv("OPENSHIELD_NIPS_RULES"); rp != "" {
		rs, err := signature.LoadRuleset(rp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openshield-worker: bad NIPS ruleset %q: %v\n", rp, err)
			os.Exit(1)
		}
		rules.Store(rs)
		fmt.Fprintf(os.Stderr, "openshield-worker: NIPS-2 content signatures active (%d rules)\n", rs.Size())
		w := signature.NewRulesetWatcher(rp)
		go w.Watch(context.Background(), 2*time.Second,
			func(rs *signature.Ruleset) {
				rules.Store(rs)
				fmt.Fprintf(os.Stderr, "openshield-worker: NIPS-2 ruleset reloaded (%d rules)\n", rs.Size())
			},
			func(err error) {
				fmt.Fprintf(os.Stderr, "openshield-worker: NIPS-2 ruleset reload failed, keeping current: %v\n", err)
			})
	} else {
		fmt.Fprintln(os.Stderr, "openshield-worker: NIPS-2 content signatures OFF (set OPENSHIELD_NIPS_RULES to enable)")
	}

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
		resp := worker.Handle(ctx, c, rules.Load(), &req)
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

// loadIndexPubKey reads the trusted operator public key for DLP index verification
// (OPENSHIELD_DLP_INDEX_PUBKEY, ADR-9), or nil when unset (legacy unsigned mode). A configured
// but unreadable/wrong-size key ABORTS: an operator asked for verification, so silently falling
// back to unsigned would defeat the control.
func loadIndexPubKey() ed25519.PublicKey {
	p := os.Getenv("OPENSHIELD_DLP_INDEX_PUBKEY")
	if p == "" {
		return nil
	}
	pub, err := os.ReadFile(p)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "openshield-worker: bad DLP index public key %q (%v) — refusing to start\n", p, err)
		os.Exit(1)
	}
	return ed25519.PublicKey(pub)
}

// loadIndexBytes reads an index file and returns the bytes to load. When pub is set, the file MUST
// be an operator-signed index of the expected kind and verify — otherwise the worker ABORTS
// (fail-closed, ADR-9): a poisoned/unsigned index that silently disabled or overwhelmed detection
// is the exact gap signing closes. When pub is nil, the raw bytes load unsigned with a loud warning.
func loadIndexBytes(path, kind string, pub ed25519.PublicKey) []byte {
	blob, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshield-worker: reading %s index %q: %v\n", kind, path, err)
		os.Exit(1)
	}
	if pub == nil {
		fmt.Fprintf(os.Stderr, "openshield-worker: WARNING loading UNVERIFIED %s index %q — set OPENSHIELD_DLP_INDEX_PUBKEY to require an operator signature (ADR-9)\n", kind, path)
		return blob
	}
	index, err := classify.VerifyIndex(blob, pub, kind)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshield-worker: %s index %q rejected (%v) — refusing to load an unverified index (ADR-9)\n", kind, path, err)
		os.Exit(1)
	}
	return index
}
