// Package signature is the NIPS-2 CONTENT-signature engine: it matches an
// operator-authored ruleset against a network flow's BODY, so the policy can
// prevent a flow whose payload trips a known-bad pattern — the half the metadata
// IOC engine (internal/nips) explicitly defers ("YARA-style body-content
// signatures are a separate, worker-side follow-up").
//
// It runs in the SANDBOXED WORKER (D72/D29/D35): the body is attacker-controlled
// content, so matching a pattern over it is a parser-class RCE surface and belongs
// behind seccomp/no-network, never in the network-capable gateway process. A match
// (a Hit) carries only the rule id and confidence — NEVER the matched bytes — so the
// classification crossing stays content-free (D10), the same discipline as a
// DLP DetectorHit.
package signature

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// DefaultMaxScan bounds how many body bytes the engine scans. A body past this is
// truncated for matching (a cap, not a bypass — the flow is still classified on what
// was scanned, and the truncation is surfaced), so a huge or adversarial body cannot
// make matching hang or exhaust memory (D13/D17).
const DefaultMaxScan = 8 << 20 // 8 MiB

// Hit is one content-signature match. RuleID is the operator rule identifier (opaque,
// for analyst traceability); it is NEVER the matched substring.
type Hit struct {
	RuleID     string
	Confidence float64
}

// pattern is one literal content requirement of a rule.
type pattern struct {
	raw    string // the literal, already lowercased when nocase
	nocase bool
}

// Rule is one content signature: it matches a body when ALL of its literal patterns
// are present AND its regex (if any) matches — Snort-like "all content: present"
// AND semantics. A rule with no matcher is rejected at parse time.
type Rule struct {
	ID         string
	patterns   []pattern
	regex      *regexp.Regexp
	nocase     bool
	Confidence float64
}

// Ruleset is a parsed, immutable set of content signatures.
type Ruleset struct {
	rules   []Rule
	maxScan int
}

// Empty reports whether the ruleset has no rules (the inert engine — no ruleset
// configured, or an empty file). An empty ruleset matches nothing.
func (rs *Ruleset) Empty() bool { return rs == nil || len(rs.rules) == 0 }

// Size reports the number of rules, for logging.
func (rs *Ruleset) Size() int {
	if rs == nil {
		return 0
	}
	return len(rs.rules)
}

// Match returns one Hit per rule that matches the body, scanning at most maxScan
// bytes. A nil/empty ruleset matches nothing. It never returns matched content.
func (rs *Ruleset) Match(body []byte) []Hit {
	if rs.Empty() {
		return nil
	}
	max := rs.maxScan
	if max <= 0 {
		max = DefaultMaxScan
	}
	scan := body
	if len(scan) > max {
		scan = scan[:max] // bounded: a body past the budget is scanned only up to it
	}
	// Lowercase the scanned window ONCE if any rule needs case-insensitive matching,
	// rather than per rule/pattern.
	var lower []byte
	needLower := false
	for i := range rs.rules {
		if rs.rules[i].needsLower() {
			needLower = true
			break
		}
	}
	if needLower {
		lower = bytes.ToLower(scan)
	}
	var out []Hit
	for i := range rs.rules {
		if rs.rules[i].matches(scan, lower) {
			out = append(out, Hit{RuleID: rs.rules[i].ID, Confidence: rs.rules[i].Confidence})
		}
	}
	return out
}

func (r *Rule) needsLower() bool {
	if r.nocase {
		for range r.patterns {
			return true
		}
	}
	for _, p := range r.patterns {
		if p.nocase {
			return true
		}
	}
	return false
}

// matches reports whether every literal pattern is present (case per the pattern/rule
// nocase) AND the regex matches. lower is the lowercased scan window (nil if unneeded).
func (r *Rule) matches(scan, lower []byte) bool {
	for _, p := range r.patterns {
		if p.nocase {
			if !bytes.Contains(lower, []byte(p.raw)) {
				return false
			}
		} else if !bytes.Contains(scan, []byte(p.raw)) {
			return false
		}
	}
	if r.regex != nil && !r.regex.Match(scan) {
		return false
	}
	return true
}

// LoadRuleset parses an operator ruleset file.
func LoadRuleset(path string) (*Ruleset, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("signature: opening ruleset: %w", err)
	}
	defer f.Close()
	return ParseRuleset(f)
}

// ParseRuleset parses the block ruleset format from a reader. The format is line
// oriented, `#` comments and blank lines skipped, and each rule is a block:
//
//	rule <id>
//	  confidence <float>      # optional, default 1.0
//	  content <literal>       # repeatable; the rest of the line is the literal
//	  nocase                  # optional; makes this rule's content matching case-insensitive
//	  regex <re2>             # optional; one per rule; the rest of the line is the regex
//	end
//
// A directive keyword takes the REST of the line verbatim as its argument, so a
// pattern or regex may contain any character (including spaces and `|`) without a
// delimiter collision. A malformed block is an error — never a silent skip, which
// would disarm a signature the operator believes is active.
func ParseRuleset(r io.Reader) (*Ruleset, error) {
	rs := &Ruleset{maxScan: DefaultMaxScan}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	var cur *Rule
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		keyword, rest, _ := strings.Cut(text, " ")
		rest = strings.TrimSpace(rest)
		switch keyword {
		case "rule":
			if cur != nil {
				return nil, fmt.Errorf("signature: line %d: 'rule' inside an unclosed rule %q (missing 'end')", line, cur.ID)
			}
			if rest == "" {
				return nil, fmt.Errorf("signature: line %d: 'rule' needs an id", line)
			}
			cur = &Rule{ID: rest, Confidence: 1.0}
		case "confidence":
			if cur == nil {
				return nil, fmt.Errorf("signature: line %d: 'confidence' outside a rule", line)
			}
			c, err := strconv.ParseFloat(rest, 64)
			if err != nil || c <= 0 || c > 1 {
				return nil, fmt.Errorf("signature: line %d: bad confidence %q (want 0<c<=1)", line, rest)
			}
			cur.Confidence = c
		case "content":
			if cur == nil {
				return nil, fmt.Errorf("signature: line %d: 'content' outside a rule", line)
			}
			if rest == "" {
				return nil, fmt.Errorf("signature: line %d: 'content' needs a literal", line)
			}
			cur.patterns = append(cur.patterns, pattern{raw: rest})
		case "nocase":
			if cur == nil {
				return nil, fmt.Errorf("signature: line %d: 'nocase' outside a rule", line)
			}
			cur.nocase = true
		case "regex":
			if cur == nil {
				return nil, fmt.Errorf("signature: line %d: 'regex' outside a rule", line)
			}
			if cur.regex != nil {
				return nil, fmt.Errorf("signature: line %d: rule %q already has a regex (one per rule)", line, cur.ID)
			}
			re, err := regexp.Compile(rest)
			if err != nil {
				return nil, fmt.Errorf("signature: line %d: bad regex: %w", line, err)
			}
			cur.regex = re
		case "end":
			if cur == nil {
				return nil, fmt.Errorf("signature: line %d: 'end' outside a rule", line)
			}
			if len(cur.patterns) == 0 && cur.regex == nil {
				return nil, fmt.Errorf("signature: line %d: rule %q has no matcher (need a content or regex)", line, cur.ID)
			}
			// Apply the rule-level nocase flag to its literal patterns and lowercase them once.
			for i := range cur.patterns {
				if cur.nocase {
					cur.patterns[i].nocase = true
				}
				if cur.patterns[i].nocase {
					cur.patterns[i].raw = strings.ToLower(cur.patterns[i].raw)
				}
			}
			rs.rules = append(rs.rules, *cur)
			cur = nil
		default:
			return nil, fmt.Errorf("signature: line %d: unknown directive %q", line, keyword)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("signature: reading ruleset: %w", err)
	}
	if cur != nil {
		return nil, fmt.Errorf("signature: rule %q is not closed with 'end'", cur.ID)
	}
	return rs, nil
}
