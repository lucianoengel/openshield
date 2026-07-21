// Package classify is the endpoint pattern classifier: format-plus-checksum
// detection for the PII types the schema names (D5, D10).
//
// It runs in the unprivileged worker, on attacker-influenced bytes. Two
// properties are load-bearing and enforced by test, not by discipline:
//
//   - It emits type + confidence + count ONLY. Matched content never leaves
//     this package; a DetectorHit has no field that could carry it. For
//     low-entropy PII a hash IS the value (D10), and a similarity-preserving
//     fingerprint reconstructs the input (D11), so neither is emitted either.
//   - It matches with RE2 (Go's regexp), which is linear-time. A backtracking
//     engine on hostile input is a denial-of-service and, because slow
//     classification fails open (D17), a Block-to-Allow bypass.
//
// Confidence is never 1.0. Classification is probabilistic; a policy that reads
// it as certainty is the mistake D4 exists to prevent.
package classify

import (
	"context"
	"fmt"
	"io"
	"regexp"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Detector matches one PII type. Scan returns the number of VALID matches and
// the confidence to report for that type; a count of 0 means no hit.
type Detector interface {
	Type() corev1.DetectorType
	Scan(text []byte) (count int, confidence float64)
}

// Classifier runs a fixed registry of detectors and returns their hits.
type Classifier struct {
	detectors []Detector
}

// New returns the default classifier: CPF, credit card, SSN, email, and the
// Phase-D2 secrets detectors (private keys, AWS keys, JWTs, vendor API tokens).
func New() *Classifier {
	return &Classifier{detectors: []Detector{
		cpf{}, creditCard{}, ssn{}, email{},
		privateKey{}, awsAccessKey{}, jwt{}, apiToken{},
	}}
}

// Classify reads the (worker-bounded) stream fully and runs every detector.
//
// A read error is returned as an error, never as an empty result: empty hits
// mean "scanned, found nothing", an error means "did not scan", and conflating
// them would let a file that crashes the reader read as clean.
func (c *Classifier) Classify(_ context.Context, r io.Reader) ([]*corev1.DetectorHit, error) {
	text, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("classify: reading input: %w", err)
	}
	var hits []*corev1.DetectorHit
	for _, d := range c.detectors {
		count, conf := d.Scan(text)
		if count == 0 {
			continue
		}
		hits = append(hits, &corev1.DetectorHit{
			DetectorType: d.Type(),
			Confidence:   conf,
			Count:        uint32(count),
		})
	}
	return hits, nil
}

// countValid runs a candidate regex, applies a validator to the normalized form
// of each candidate, and counts distinct valid values. The normalized-value set
// lives only for this call and is never emitted — de-duplication so a repeated
// fixture does not inflate the count, without exposing the values themselves.
func countValid(re *regexp.Regexp, text []byte, normalize func([]byte) string, valid func(string) bool) int {
	seen := map[string]struct{}{}
	for _, m := range re.FindAll(text, -1) {
		n := normalize(m)
		if !valid(n) {
			continue
		}
		seen[n] = struct{}{}
	}
	return len(seen)
}

// stripNonDigits keeps only ASCII digits — the normalized form for the numeric
// detectors.
func stripNonDigits(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	return string(out)
}
