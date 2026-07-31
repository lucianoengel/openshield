// Package suricata parses a defined subset of the Suricata/Snort rule language (NIPS-11).
//
// WHY IT MATTERS THAT THE RULES ARE THEIRS AND NOT OURS. Every deployment that has ever run an IDS has
// rules already — ET Open, a vendor feed, ten years of an analyst's own. A product with its own rule
// format asks them to rewrite all of it, which nobody does, so the rules that would have caught something
// stay in the file they were already in. Speaking the language they are written in is the difference
// between a signature engine that is used and one that is configured.
//
// THE SUBSET IS THE WHOLE DESIGN, AND SO IS WHAT HAPPENS OUTSIDE IT.
//
// The full grammar is hundreds of keywords, several protocol parsers, flow state, datasets and Lua. This
// implements a body-content subset. What it does with everything else is the part that matters: a rule
// using a keyword outside the subset is REFUSED, by name, and counted at load.
//
// That refusal is not pedantry, it is the only safe behaviour. A rule engine that silently ignores what
// it does not understand does not match LESS — it matches DIFFERENTLY, and almost always MORE. Ignore
// `http.uri` and a rule scoped to a URI matches the same bytes anywhere in a body. Ignore `depth:20` and
// a rule looking at a header prefix matches a megabyte downstream. The operator sees a loaded rule with
// their sid on it, firing on traffic it was never written for, and has no way to tell the engine
// silently rewrote it.
//
// PCRE IS REFUSED FOR THE SAME REASON, and it deserves naming separately because accepting it is so
// tempting. Suricata's `pcre` is PCRE: backreferences, lookaround, possessive quantifiers. Go's regexp is
// RE2, which has none of those and is not a subset relationship in the direction that would help — a
// rule that compiles under both can still match different things. Running an operator's PCRE rule through
// RE2 and reporting a match under their sid is asserting something about their rule that is not true.
package suricata

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Action is a rule's action. The vocabulary is closed: an unknown action is a rule this engine cannot
// honour, and treating it as `alert` would silently downgrade a `drop`.
type Action string

const (
	ActionAlert  Action = "alert"
	ActionDrop   Action = "drop"
	ActionReject Action = "reject"
	ActionPass   Action = "pass"
)

// Rule is one parsed rule.
type Rule struct {
	Action Action
	Proto  string // tcp | udp | http | tls | dns | ip | any — matched against the flow's protocol
	Msg    string
	SID    string
	Rev    string
	// Contents are the content requirements, IN ORDER. Order is load-bearing: `distance` and `within`
	// are relative to the END of the previous match, so reordering them changes what the rule means.
	Contents []Content
	// Raw is the rule as written, kept so an analyst can see exactly what was loaded.
	Raw string
}

// Content is one content requirement with its modifiers.
type Content struct {
	Pattern   []byte
	Negated   bool // content:!"x" — must NOT be present in the constrained region
	Nocase    bool
	Offset    int  // match must start at or after this byte
	Depth     int  // match must END within Offset+Depth; 0 = unbounded
	Distance  int  // match must start at least this far after the previous match's end
	HasDist   bool // distance:0 is meaningful, so presence is tracked separately
	Within    int  // match must start within this many bytes of the previous match's end
	HasWithin bool
	EndsWith  bool // must match at the very end of the buffer
}

// supported names every option keyword this implementation honours.
//
// A map rather than a switch so the REFUSAL can name the keyword and the SET can be reported: an
// operator loading a community ruleset needs to know which of their rules did not load and why, not that
// "some rules failed".
var supported = map[string]bool{
	"msg": true, "sid": true, "rev": true, "content": true, "nocase": true,
	"depth": true, "offset": true, "distance": true, "within": true,
	"startswith": true, "endswith": true,
	// Accepted and carried as metadata only — they do not change what is matched, so honouring them is
	// not required for the rule to mean what it says.
	"classtype": true, "priority": true, "reference": true, "metadata": true, "rev:": true,
}

// Supported returns the honoured keyword set, sorted, so an operator can be told what this engine speaks
// rather than discovering it one refused rule at a time.
func Supported() []string {
	out := make([]string, 0, len(supported))
	for k := range supported {
		if strings.HasSuffix(k, ":") {
			continue
		}
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// Parse decodes one Suricata rule line.
func Parse(line string) (Rule, error) {
	raw := strings.TrimSpace(line)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return Rule{}, errComment
	}
	open := strings.Index(raw, "(")
	if open < 0 || !strings.HasSuffix(raw, ")") {
		return Rule{}, fmt.Errorf("suricata: rule has no option block")
	}
	header := strings.Fields(raw[:open])
	// action proto src sport dir dst dport
	if len(header) != 7 {
		return Rule{}, fmt.Errorf("suricata: header has %d fields, want 7 "+
			"(action proto src sport direction dst dport)", len(header))
	}
	r := Rule{Raw: raw, Proto: strings.ToLower(header[1])}
	switch Action(strings.ToLower(header[0])) {
	case ActionAlert:
		r.Action = ActionAlert
	case ActionDrop:
		r.Action = ActionDrop
	case ActionReject:
		r.Action = ActionReject
	case ActionPass:
		r.Action = ActionPass
	default:
		// Never defaulted to alert: a `drop` silently downgraded to an alert is a rule the operator
		// believes is preventing something and which is only watching.
		return Rule{}, fmt.Errorf("suricata: unknown action %q", header[0])
	}

	if err := parseOptions(&r, raw[open+1:len(raw)-1]); err != nil {
		return Rule{}, err
	}
	if len(r.Contents) == 0 {
		// A rule with no content requirement matches EVERY flow of its protocol. Loading one would be a
		// deployment where a single ruleset line alerts on all traffic, which reads as the engine being
		// broken rather than as the rule being wrong.
		return Rule{}, fmt.Errorf("suricata: rule %s has no content match — it would match every flow",
			r.SID)
	}
	if r.SID == "" {
		return Rule{}, fmt.Errorf("suricata: rule has no sid — a hit that cannot be traced to a rule is " +
			"an alert an analyst cannot act on")
	}
	return r, nil
}

// errComment marks a line that is not a rule. Exported behaviour is via ParseRuleset, which skips them.
var errComment = fmt.Errorf("suricata: comment or blank line")

// parseOptions walks the option block, honouring the subset and refusing the rest BY NAME.
func parseOptions(r *Rule, body string) error {
	for _, opt := range splitOptions(body) {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		key, val, hasVal := strings.Cut(opt, ":")
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		if !supported[key] {
			return fmt.Errorf("suricata: rule uses %q, which this engine does not implement. It is "+
				"REFUSED rather than ignored: a rule engine that drops a keyword it does not understand "+
				"does not match less, it matches DIFFERENTLY and usually more — a rule scoped by that "+
				"keyword would fire on traffic it was never written for, under the operator's own sid",
				key)
		}
		switch key {
		case "msg":
			r.Msg = trimQuotes(val)
		case "sid":
			r.SID = val
		case "rev":
			r.Rev = val
		case "classtype", "priority", "reference", "metadata":
			// Carried as written; they do not change what is matched.
		case "content":
			c, err := parseContent(val, hasVal)
			if err != nil {
				return err
			}
			r.Contents = append(r.Contents, c)
		case "nocase", "startswith", "endswith", "depth", "offset", "distance", "within":
			if len(r.Contents) == 0 {
				return fmt.Errorf("suricata: %q appears before any content — it modifies the content "+
					"before it, and one with nothing to modify is a rule that does not say what its "+
					"author meant", key)
			}
			if err := applyModifier(&r.Contents[len(r.Contents)-1], key, val); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyModifier applies one content modifier to the content it follows.
func applyModifier(c *Content, key, val string) error {
	num := func() (int, error) {
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("suricata: %s:%q is not a non-negative number", key, val)
		}
		return n, nil
	}
	switch key {
	case "nocase":
		c.Nocase = true
	case "startswith":
		// Equivalent to offset:0 with the match required at the very start.
		c.Offset, c.Depth = 0, len(c.Pattern)
	case "endswith":
		c.EndsWith = true
	case "depth":
		n, err := num()
		if err != nil {
			return err
		}
		c.Depth = n
	case "offset":
		n, err := num()
		if err != nil {
			return err
		}
		c.Offset = n
	case "distance":
		n, err := num()
		if err != nil {
			return err
		}
		c.Distance, c.HasDist = n, true
	case "within":
		n, err := num()
		if err != nil {
			return err
		}
		c.Within, c.HasWithin = n, true
	}
	return nil
}

// parseContent decodes a content value, including Suricata's |hex| byte escapes.
//
// The hex form is not a nicety: it is how every rule that matches a binary protocol is written, and a
// parser that only handled printable text would refuse the rules most worth having.
func parseContent(val string, hasVal bool) (Content, error) {
	if !hasVal {
		return Content{}, fmt.Errorf("suricata: content with no value")
	}
	c := Content{}
	if strings.HasPrefix(val, "!") {
		c.Negated = true
		val = strings.TrimSpace(val[1:])
	}
	s := trimQuotes(val)
	if s == "" {
		return Content{}, fmt.Errorf("suricata: empty content — it would match everywhere")
	}
	var out []byte
	for i := 0; i < len(s); {
		if s[i] != '|' {
			// Suricata escapes these three inside a content string.
			if s[i] == '\\' && i+1 < len(s) {
				i++
			}
			out = append(out, s[i])
			i++
			continue
		}
		end := strings.IndexByte(s[i+1:], '|')
		if end < 0 {
			return Content{}, fmt.Errorf("suricata: unterminated |hex| block in content")
		}
		hexPart := strings.ReplaceAll(s[i+1:i+1+end], " ", "")
		b, err := hex.DecodeString(hexPart)
		if err != nil {
			return Content{}, fmt.Errorf("suricata: bad |hex| block %q: %w", hexPart, err)
		}
		out = append(out, b...)
		i += end + 2
	}
	c.Pattern = out
	return c, nil
}

// splitOptions splits an option block on semicolons that are NOT inside a quoted string.
//
// Naive splitting breaks every rule whose msg contains a semicolon, which is a lot of them — and it
// breaks them by shifting the remaining options, so the rule loads and means something else.
func splitOptions(body string) []string {
	var out []string
	var cur strings.Builder
	inQuote, esc := false, false
	for i := 0; i < len(body); i++ {
		ch := body[i]
		switch {
		case esc:
			cur.WriteByte(ch)
			esc = false
		case ch == '\\':
			cur.WriteByte(ch)
			esc = true
		case ch == '"':
			inQuote = !inQuote
			cur.WriteByte(ch)
		case ch == ';' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
