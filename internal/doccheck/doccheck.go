// Package doccheck guards the project's honesty on its claim surfaces (T-029).
//
// The project's credibility rests on "tamper-evident, not tamper-proof" and
// "detection, not prevention". A careless README edit could erase that. But the
// naive guard is worse than none: a denylist grep for the forbidden words
// false-positived on four HONEST negated uses (2026-07-20), because this
// project's discipline consists of discussing exactly those words in negation.
// So this check tells a claim from its denial: it flags an UNQUALIFIED overclaim
// and passes negated discussion, an escaped use, and the docs that exist to
// reason out loud.
package doccheck

import (
	"fmt"
	"regexp"
	"strings"
)

// ClaimSurfaces is the explicit allowlist of files a claim can be made on. It is
// an allowlist, not "all docs", because docs/ is where the project reasons out
// loud — including about what it CANNOT do — and scanning it would recreate the
// false-positive failure the naive grep suffered.
var ClaimSurfaces = []string{"README.md"}

// forbidden are overclaiming terms, each mapping to a specific false promise the
// threat model forbids: tamper-proofing, prevention, absolutes. Matched
// case-insensitively after markdown emphasis is stripped.
var forbidden = []*regexp.Regexp{
	regexp.MustCompile(`(?i)tamper-?proof`),
	regexp.MustCompile(`(?i)unhackable`),
	regexp.MustCompile(`(?i)impenetrable`),
	regexp.MustCompile(`(?i)(?:fully|100%) secure`),
	regexp.MustCompile(`(?i)prevents (?:exfiltration|data loss)`),
	regexp.MustCompile(`(?i)guarantees? (?:security|safety|protection|your data)`),
}

// negation marks a line as discussion rather than a claim. "not", "cannot",
// "impossible" etc. are exactly how the honest README states its limits.
var negation = regexp.MustCompile(`(?i)\b(cannot|can't|not|never|no|isn't|impossible|does ?n't|without)\b`)

// emphasis is markdown bold/italic markers, stripped before matching so
// `tamper-*proof*` is caught the same as `tamperproof`.
var emphasis = regexp.MustCompile(`[*_]`)

// allowEscape permits a deliberate use: `<!-- allow: <term> -->`.
var allowEscape = regexp.MustCompile(`<!--\s*allow:\s*(.+?)\s*-->`)

// Violation is one unqualified overclaim.
type Violation struct {
	Line int
	Term string
	Text string
}

func (v Violation) String() string {
	return fmt.Sprintf("line %d: unqualified overclaim %q in: %s", v.Line, v.Term, strings.TrimSpace(v.Text))
}

// ScanClaimSurface reports unqualified overclaims. A match is suppressed when the
// line is negated, or carries an allow-escape on it or the line immediately
// above.
func ScanClaimSurface(text string) []Violation {
	lines := strings.Split(text, "\n")
	var out []Violation
	for i, raw := range lines {
		clean := emphasis.ReplaceAllString(raw, "")

		// Escape on this line or the one above.
		escaped := map[string]bool{}
		collectEscapes(raw, escaped)
		if i > 0 {
			collectEscapes(lines[i-1], escaped)
		}

		negated := negation.MatchString(clean)

		for _, re := range forbidden {
			m := re.FindString(clean)
			if m == "" {
				continue
			}
			if negated {
				continue // discussion, not a claim
			}
			if escaped[strings.ToLower(strings.TrimSpace(m))] || escapedAny(escaped) {
				continue
			}
			out = append(out, Violation{Line: i + 1, Term: m, Text: raw})
		}
	}
	return out
}

func collectEscapes(line string, into map[string]bool) {
	for _, m := range allowEscape.FindAllStringSubmatch(line, -1) {
		into[strings.ToLower(strings.TrimSpace(m[1]))] = true
	}
}

// escapedAny reports whether a bare `<!-- allow: ... -->` was present; a term
// escape covers any forbidden match on its line, since the author has signalled
// a deliberate discussion there.
func escapedAny(escaped map[string]bool) bool { return len(escaped) > 0 }

var dNumber = regexp.MustCompile(`\*\*D(\d+)\*\*`)

// CheckDecisionRegister fails if any D-number is assigned more than once. A
// duplicate is the drift that lets the single source of truth quietly diverge —
// two decisions colliding on a number, or a copy-paste that reused one.
func CheckDecisionRegister(text string) error {
	seen := map[string]int{}
	for _, m := range dNumber.FindAllStringSubmatch(text, -1) {
		seen[m[1]]++
	}
	var dups []string
	for n, count := range seen {
		if count > 1 {
			dups = append(dups, fmt.Sprintf("D%s (x%d)", n, count))
		}
	}
	if len(dups) > 0 {
		return fmt.Errorf("decision register has duplicate D-numbers: %s", strings.Join(dups, ", "))
	}
	return nil
}
