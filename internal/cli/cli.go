// Package cli holds the openshieldctl command logic, separated from main so it
// can be tested without spawning a process. The rule this package enforces: a
// timeline is never shown without its verification state, and "cannot tell" is
// never rendered as "fine".
package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
)

// Exit codes are part of the contract: a scheduled `verify` must be able to act
// on the outcome without parsing output. "Cannot tell" (unavailable) and
// "tampered" (inconsistent) are DIFFERENT codes because they demand different
// operator responses — treating a database outage as tamper-detection would
// cry wolf, and treating tampering as an outage would miss the wolf.
const (
	ExitOK           = 0
	ExitInconsistent = 3
	ExitUnavailable  = 4
)

// Reader is the read surface the CLI needs. postgres.Ledger satisfies it; a
// fake satisfies it in tests.
type Reader interface {
	Verify(ctx context.Context, expectedAnchor ed25519.PublicKey) (core.VerifyResult, error)
	Entries(ctx context.Context) ([]*core.Entry, error)
}

// Filter narrows which entries a timeline renders. A zero Filter matches all.
type Filter struct {
	Subject string
	EventID string
	Since   time.Time
	Until   time.Time
}

func (f Filter) matches(e *core.Entry) bool {
	if f.Subject != "" && e.SubjectID != f.Subject {
		return false
	}
	if f.EventID != "" && (e.Decision == nil || e.Decision.GetEventId() != f.EventID) {
		return false
	}
	if !f.Since.IsZero() && e.AppendedAt.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.AppendedAt.After(f.Until) {
		return false
	}
	return true
}

// ExitCodeFor maps a verification outcome to the process exit code.
func ExitCodeFor(res core.VerifyResult, err error) int {
	if errors.Is(err, core.ErrLedgerUnavailable) {
		return ExitUnavailable
	}
	if err != nil {
		// An unexpected error is not the same as a clean chain. Fail as
		// "cannot tell" rather than claim consistency we did not establish.
		return ExitUnavailable
	}
	if !res.Consistent {
		return ExitInconsistent
	}
	return ExitOK
}

// Verify runs verification only and returns the exit code, after writing a
// one-line human summary. For cron and CI.
func Verify(ctx context.Context, w io.Writer, r Reader, anchor ed25519.PublicKey) int {
	res, err := r.Verify(ctx, anchor)
	code := ExitCodeFor(res, err)
	switch code {
	case ExitUnavailable:
		fmt.Fprintf(w, "UNAVAILABLE: cannot verify the ledger: %v\n", err)
	case ExitInconsistent:
		fmt.Fprintf(w, "TAMPERED: %s\n", res)
	default:
		fmt.Fprintf(w, "OK: %s\n", res)
	}
	return code
}

// Timeline verifies, prints the verification header, then the filtered entries
// in sequence order. Rows from the first break onward are marked and still
// printed — an operator investigating tampering must see the tampered data.
// Returns the same exit code as Verify.
func Timeline(ctx context.Context, w io.Writer, r Reader, anchor ed25519.PublicKey, f Filter) int {
	res, err := r.Verify(ctx, anchor)
	code := ExitCodeFor(res, err)

	writeHeader(w, res, err, anchor)
	if code == ExitUnavailable {
		return code
	}

	entries, err := r.Entries(ctx)
	if err != nil {
		fmt.Fprintf(w, "UNAVAILABLE: cannot read entries: %v\n", err)
		return ExitUnavailable
	}

	fmt.Fprintln(w, "---")
	var shown int
	for _, e := range entries {
		if !f.matches(e) {
			continue
		}
		shown++
		mark := "  "
		if res.FirstBreak != nil && e.Sequence >= *res.FirstBreak {
			mark = "!!" // at or after the first break: possibly tampered
		}
		fmt.Fprintf(w, "%s seq=%d at=%s subject=%s %s\n",
			mark, e.Sequence, e.AppendedAt.UTC().Format(time.RFC3339Nano),
			redactEmpty(e.SubjectID), describe(e))
	}
	if shown == 0 {
		fmt.Fprintln(w, "(no entries match the filter)")
	}
	return code
}

func writeHeader(w io.Writer, res core.VerifyResult, err error, anchor ed25519.PublicKey) {
	if errors.Is(err, core.ErrLedgerUnavailable) || (err != nil) {
		fmt.Fprintf(w, "VERIFICATION: UNAVAILABLE (%v)\n", err)
		return
	}
	state := "CONSISTENT"
	if !res.Consistent {
		state = "INCONSISTENT"
	}
	fmt.Fprintf(w, "VERIFICATION: %s  range=[%d,%d] entries=%d completeness=%s\n",
		state, res.FromSequence, res.ToSequence, res.Entries, res.Completeness)
	// When an external witness covers part of the chain, name the boundary: the
	// prefix is provably complete, the tail after it is not (T-019).
	if res.Completeness != core.CompletenessAnchored && res.AnchoredThrough > 0 {
		fmt.Fprintf(w, "  anchors: complete through seq=%d, UNVERIFIED after (nothing witnesses the tail)\n",
			res.AnchoredThrough)
	} else if res.Completeness == core.CompletenessAnchored {
		fmt.Fprintf(w, "  anchors: an external witness attests the full chain\n")
	}
	if anchor == nil {
		fmt.Fprintln(w, "  anchor: NONE supplied — origin and completeness are UNVERIFIED")
	} else {
		fmt.Fprintln(w, "  anchor: pinned to a caller-supplied key")
	}
	if !res.Consistent && res.FirstBreak != nil {
		fmt.Fprintf(w, "  FIRST BREAK at seq=%d: %s\n", *res.FirstBreak, res.Reason)
		fmt.Fprintln(w, "  rows marked !! are at or after the break and may be forged")
	} else if res.Reason != "" {
		fmt.Fprintf(w, "  note: %s\n", res.Reason)
	}
}

func describe(e *core.Entry) string {
	if e.Decision != nil {
		return fmt.Sprintf("action=%s confidence=%.2f event=%s",
			e.Decision.GetAction(), e.Decision.GetConfidence(), e.Decision.GetEventId())
	}
	// A terminal outcome that produced no Decision — a timeout or a failure.
	// Rendering it as a blank Decision would be the exact conflation the
	// outcome columns exist to prevent.
	return fmt.Sprintf("outcome=%s stage=%s", e.OutcomeKind, e.OutcomeStage)
}

func redactEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ExportAnchor writes the anchor public key as PEM, prefixed with the limit of
// what it attests. An anchor captured from a host that could later be
// compromised proves nothing UNLESS it was captured while the host was trusted;
// saying so is the difference between a usable out-of-band anchor and security
// theatre.
func ExportAnchor(w io.Writer, anchor ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(anchor)
	if err != nil {
		return fmt.Errorf("marshalling anchor: %w", err)
	}
	notice := strings.Join([]string{
		"# OpenShield audit-ledger anchor (Ed25519 public key).",
		"# Capture this NOW, while this host is trusted, and store it OUT OF BAND.",
		"# It lets you later detect rewriting of history that predates a compromise.",
		"# It is NOT independent proof: an anchor exported from an already-compromised",
		"# host attests to nothing. External witnessing is T-019.",
		"",
	}, "\n")
	if _, err := io.WriteString(w, notice); err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
