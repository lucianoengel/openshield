package suricata

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MATCHING (NIPS-11).
//
// A rule matches when EVERY content requirement is satisfied, in order, against the flow body — the same
// AND semantics Suricata gives a single-buffer rule. The ordering matters because `distance` and `within`
// are relative to where the PREVIOUS content matched, so the rule is a sequence and not a set.
//
// WHAT THIS IS NOT, said here because the parser's refusals only cover keywords and this covers scope.
// There is no stream reassembly, no flow state, no protocol parser: matching happens over ONE buffer,
// the body the pipeline already holds. A rule whose meaning depends on any of those is refused at parse
// time, so what runs here is exactly the rules whose meaning survives being evaluated this way.

// Hit is one rule match. It carries the rule's identity and NEVER the matched bytes — the same
// content-free crossing every classifier here obeys (D10/D29): a hit is evidence that a rule fired, not
// a copy of what it fired on.
type Hit struct {
	SID    string
	Msg    string
	Action Action
}

// Ruleset is a parsed, immutable set of rules plus what would not load.
type Ruleset struct {
	rules []Rule
	// Refused records every rule this engine would not honour, with the reason. It is part of the
	// ruleset rather than a log line because "which of my rules are actually running" is a question an
	// operator must be able to ask AFTER the load, not only at the moment it happened.
	Refused []Refusal
}

// Refusal is one rule that did not load.
type Refusal struct {
	Line   int
	SID    string
	Reason string
}

// Size reports how many rules are active.
func (rs *Ruleset) Size() int {
	if rs == nil {
		return 0
	}
	return len(rs.rules)
}

// Empty reports whether nothing will ever match.
func (rs *Ruleset) Empty() bool { return rs.Size() == 0 }

// ParseRuleset reads a Suricata rule file.
//
// A rule this engine cannot honour does NOT fail the load — it is refused, recorded, and the rest load.
// That is the opposite of the discipline used for a routing table or an escalation ladder, and the
// difference is who wrote the file: a community ruleset is thousands of rules from someone else, and
// refusing the whole file because forty of them use `flowbits` would mean nobody ever loads one. What
// must not happen is a refusal that is SILENT, so every one is recorded and the caller is expected to
// report the count.
func ParseRuleset(r io.Reader) (*Ruleset, error) {
	rs := &Ruleset{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		rule, err := Parse(text)
		if errors.Is(err, errComment) {
			continue
		}
		if err != nil {
			rs.Refused = append(rs.Refused, Refusal{Line: line, SID: sidOf(text), Reason: err.Error()})
			continue
		}
		rs.rules = append(rs.rules, rule)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("suricata: reading rules: %w", err)
	}
	return rs, nil
}

// sidOf makes a best effort to name the rule in a refusal, so an operator can find the line they need to
// look at rather than being told a number.
func sidOf(text string) string {
	i := strings.Index(text, "sid:")
	if i < 0 {
		return ""
	}
	rest := text[i+4:]
	if j := strings.IndexAny(rest, ";)"); j >= 0 {
		return strings.TrimSpace(rest[:j])
	}
	return ""
}

// Match returns a hit per rule satisfied by the body.
//
// proto is the flow's protocol; a rule scoped to a protocol only matches a flow of that protocol, with
// `ip` and `any` matching everything. Scoping is applied FIRST because it is the cheap check and because
// a rule written for tcp firing on a udp flow is a false positive the rule's author already excluded.
func (rs *Ruleset) Match(body []byte, proto string) []Hit {
	if rs.Empty() || len(body) == 0 {
		return nil
	}
	proto = strings.ToLower(proto)
	var hits []Hit
	for _, r := range rs.rules {
		if !protoMatches(r.Proto, proto) {
			continue
		}
		if matchContents(r.Contents, body) {
			hits = append(hits, Hit{SID: r.SID, Msg: r.Msg, Action: r.Action})
		}
	}
	return hits
}

func protoMatches(ruleProto, flowProto string) bool {
	switch ruleProto {
	case "", "ip", "any":
		return true
	}
	if flowProto == "" {
		// A flow with no protocol recorded is not claimed to be any particular one. Matching a
		// protocol-scoped rule against it would attribute the hit to a protocol nobody observed.
		return false
	}
	return ruleProto == flowProto
}

// matchContents walks the content sequence, threading the previous match's end through so `distance` and
// `within` mean what Suricata says they mean.
func matchContents(cs []Content, body []byte) bool {
	prevEnd := -1
	for _, c := range cs {
		hay := body
		pat := c.Pattern
		if c.Nocase {
			hay = bytes.ToLower(body)
			pat = bytes.ToLower(pat)
		}
		start, end := searchWindow(c, len(body), prevEnd)
		if start > end || start > len(hay) {
			// The window is empty. For a POSITIVE content that is a failure; for a NEGATED one it is
			// vacuously satisfied — there is nowhere for the forbidden bytes to be.
			if c.Negated {
				continue
			}
			return false
		}
		if end > len(hay) {
			end = len(hay)
		}
		idx := bytes.Index(hay[start:end], pat)
		if c.EndsWith && idx >= 0 {
			// The match must sit at the very end of the buffer, not merely inside the window.
			if start+idx+len(pat) != len(body) {
				idx = -1
				if tail := len(body) - len(pat); tail >= start && tail < end &&
					bytes.Equal(hay[tail:tail+len(pat)], pat) {
					idx = tail - start
				}
			}
		}
		if c.Negated {
			if idx >= 0 {
				return false
			}
			continue // a negated content does NOT advance the cursor: there is no match to be relative to
		}
		if idx < 0 {
			return false
		}
		prevEnd = start + idx + len(pat)
	}
	return true
}

// searchWindow computes the byte range a content may match in, from its modifiers and the previous
// match's end.
//
// Returning a HALF-OPEN [start, end) window rather than applying the constraints after a search is what
// makes `depth` mean "the match must END within" rather than "the match must START within" — the two
// differ by the pattern length, and getting it wrong makes a rule fire on traffic just past the boundary
// its author drew.
func searchWindow(c Content, bodyLen, prevEnd int) (start, end int) {
	start, end = 0, bodyLen
	if c.Offset > 0 {
		start = c.Offset
	}
	if c.HasDist && prevEnd >= 0 {
		if s := prevEnd + c.Distance; s > start {
			start = s
		}
	}
	if c.HasWithin && prevEnd >= 0 {
		// `within:N` bounds where the match may START, relative to the previous end — and the match must
		// still fit, so the searchable region ends N bytes past that plus the pattern length.
		if e := prevEnd + c.Within + len(c.Pattern); e < end {
			end = e
		}
	}
	if c.Depth > 0 {
		base := c.Offset
		if c.HasDist && prevEnd >= 0 {
			base = prevEnd + c.Distance
		}
		if e := base + c.Depth; e < end {
			end = e
		}
	}
	if start < 0 {
		start = 0
	}
	if end > bodyLen {
		end = bodyLen
	}
	return start, end
}
