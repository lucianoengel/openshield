package suricata_test

import (
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/suricata"
)

// NIPS-11 — THE SURICATA RULE LANGUAGE.
//
// Every deployment that has ever run an IDS has rules already. A product with its own format asks them to
// rewrite all of it, which nobody does, so the rules that would have caught something stay in the file
// they were already in.
//
// The subset is the design, and what happens OUTSIDE it is the part that matters.

// THE HEADLINE: a real rule loads and matches the body it was written for.
func TestARealRuleLoadsAndMatches(t *testing.T) {
	const rule = `alert tcp any any -> any any (msg:"exfil marker"; content:"BEGIN "; content:"SECRET"; ` +
		`distance:0; sid:1000001; rev:3;)`
	r, err := suricata.Parse(rule)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if r.SID != "1000001" || r.Msg != "exfil marker" || r.Action != suricata.ActionAlert {
		t.Fatalf("header/options not parsed: %+v", r)
	}

	rs, err := suricata.ParseRuleset(strings.NewReader(rule))
	if err != nil {
		t.Fatal(err)
	}
	if hits := rs.Match([]byte("xx BEGIN THE SECRET yy"), "tcp"); len(hits) != 1 || hits[0].SID != "1000001" {
		t.Fatalf("hits = %+v, want one for sid 1000001", hits)
	}
	// The sequence is ordered: SECRET must follow BEGIN. Reversed, the rule does not match.
	if hits := rs.Match([]byte("SECRET then BEGIN "), "tcp"); len(hits) != 0 {
		t.Fatalf("the rule matched with its contents out of order — `distance` is relative to the "+
			"PREVIOUS match, so a rule is a sequence and not a set: %+v", hits)
	}
	// And a hit carries NO matched bytes.
	for _, h := range rs.Match([]byte("xx BEGIN THE SECRET yy"), "tcp") {
		if strings.Contains(h.Msg, "SECRET") {
			t.Error("the hit carried matched content — a hit is evidence a rule fired, not a copy of " +
				"what it fired on")
		}
	}
}

// AN UNSUPPORTED KEYWORD IS REFUSED BY NAME, never ignored.
//
// A rule engine that drops what it does not understand does not match LESS — it matches DIFFERENTLY and
// almost always MORE. Ignore `http.uri` and a rule scoped to a URI matches the same bytes anywhere in a
// body; ignore `depth:20` and a header rule matches a megabyte downstream. The operator sees a loaded
// rule with their sid on it, firing on traffic it was never written for.
//
// Mutation (skip unknown keywords instead of erroring): every rule below loads → FAIL.
func TestAnUnsupportedKeywordIsRefusedByName(t *testing.T) {
	for _, tc := range []struct{ name, rule, keyword string }{
		{"http.uri", `alert http any any -> any any (content:"x"; http.uri; sid:1;)`, "http.uri"},
		{"pcre", `alert tcp any any -> any any (content:"x"; pcre:"/a(?=b)/"; sid:2;)`, "pcre"},
		{"flowbits", `alert tcp any any -> any any (content:"x"; flowbits:set,a; sid:3;)`, "flowbits"},
		{"threshold", `alert tcp any any -> any any (content:"x"; threshold:type limit,count 1; sid:4;)`, "threshold"},
		{"dataset", `alert tcp any any -> any any (content:"x"; dataset:isset,bad; sid:5;)`, "dataset"},
		{"flow", `alert tcp any any -> any any (content:"x"; flow:established; sid:6;)`, "flow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := suricata.Parse(tc.rule)
			if err == nil {
				t.Fatalf("a rule using %q loaded — ignoring a keyword does not narrow a rule, it "+
					"REWRITES it, and the operator has no way to tell", tc.keyword)
			}
			if !strings.Contains(err.Error(), tc.keyword) {
				t.Errorf("the refusal does not name %q: %v — an operator loading a community ruleset "+
					"needs to know WHICH of their rules did not load and why", tc.keyword, err)
			}
		})
	}
}

// PCRE IS REFUSED FOR A REASON WORTH STATING SEPARATELY.
//
// Suricata's `pcre` is PCRE: backreferences, lookaround, possessive quantifiers. Go's regexp is RE2,
// which has none of those — a rule that compiles under both can still match different things. Running an
// operator's PCRE rule through RE2 and reporting a match under their sid asserts something about their
// rule that is not true.
func TestPCREIsRefusedRatherThanApproximated(t *testing.T) {
	// A rule whose regex uses lookahead, which RE2 cannot express at all.
	_, err := suricata.Parse(`alert tcp any any -> any any (content:"x"; pcre:"/foo(?=bar)/"; sid:7;)`)
	if err == nil {
		t.Fatal("a PCRE rule was accepted — Go's RE2 cannot express lookahead, so the rule that ran " +
			"would not be the rule that was written, under the operator's own sid")
	}
}

// A RULE WITH NO CONTENT, OR NO SID, IS REFUSED.
//
// The first would match every flow of its protocol — one ruleset line alerting on all traffic reads as
// the engine being broken. The second produces a hit an analyst cannot trace to anything.
func TestRulesThatCannotBeActedOnAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, rule string }{
		{"no content", `alert tcp any any -> any any (msg:"everything"; sid:8;)`},
		{"no sid", `alert tcp any any -> any any (content:"x";)`},
		{"no option block", `alert tcp any any -> any any`},
		{"short header", `alert tcp any any (content:"x"; sid:9;)`},
		{"unknown action", `warn tcp any any -> any any (content:"x"; sid:10;)`},
		{"empty content", `alert tcp any any -> any any (content:""; sid:11;)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := suricata.Parse(tc.rule); err == nil {
				t.Fatalf("accepted a rule that cannot be acted on: %s", tc.rule)
			}
		})
	}
}

// AN UNKNOWN ACTION IS NOT DOWNGRADED TO ALERT.
//
// A `drop` silently becoming an alert is a rule the operator believes is preventing something and which
// is only watching — the worst direction for a mistake in a prevention engine.
func TestTheActionIsCarriedAndNeverDowngraded(t *testing.T) {
	r, err := suricata.Parse(`drop tcp any any -> any any (content:"x"; sid:12;)`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Action != suricata.ActionDrop {
		t.Fatalf("action = %q, want drop — an action silently downgraded to alert is a rule the "+
			"operator believes is preventing and which is only watching", r.Action)
	}
}

// |HEX| CONTENT IS DECODED. It is how every rule matching a binary protocol is written, and a parser
// that only handled printable text would refuse the rules most worth having.
func TestHexContentIsDecoded(t *testing.T) {
	rs, err := suricata.ParseRuleset(strings.NewReader(
		`alert tcp any any -> any any (content:"|4d 5a|"; sid:13;)`))
	if err != nil {
		t.Fatal(err)
	}
	if rs.Size() != 1 {
		t.Fatalf("the hex rule did not load: %+v", rs.Refused)
	}
	if hits := rs.Match([]byte{0x00, 0x4d, 0x5a, 0x90}, "tcp"); len(hits) != 1 {
		t.Fatal("the |4d 5a| (MZ) content did not match a PE header — binary rules are the ones most " +
			"worth having")
	}
	if hits := rs.Match([]byte("MZ is just text"), "tcp"); len(hits) != 1 {
		t.Fatal("the decoded bytes should match their ASCII equivalent too")
	}
}

// DEPTH BOUNDS WHERE THE MATCH ENDS, not where it starts.
//
// The two differ by the pattern length, and getting it wrong makes a rule fire on traffic just past the
// boundary its author drew.
//
// Mutation (treat depth as bounding the START): "SECRET" at offset 6 with depth:8 matches, though it
// ends at 12 → FAIL.
func TestDepthBoundsWhereTheMatchEnds(t *testing.T) {
	rs, _ := suricata.ParseRuleset(strings.NewReader(
		`alert tcp any any -> any any (content:"SECRET"; depth:8; sid:14;)`))

	// Ends at byte 6 — inside depth:8.
	if hits := rs.Match([]byte("SECRET....................."), "tcp"); len(hits) != 1 {
		t.Fatal("a match entirely inside depth:8 did not fire")
	}
	// Starts at 6, ends at 12 — outside depth:8, though it STARTS inside it.
	if hits := rs.Match([]byte("xxxxxxSECRET..............."), "tcp"); len(hits) != 0 {
		t.Fatalf("a match that ENDS past depth:8 fired (%+v) — depth bounds the end, and the two differ "+
			"by the pattern length, which is exactly the traffic just past the boundary the author drew",
			hits)
	}
}

// OFFSET, DISTANCE AND WITHIN CONSTRAIN THE WINDOW.
func TestOffsetDistanceAndWithinConstrainTheWindow(t *testing.T) {
	body := []byte("AAAAABEGIN....SECRET")

	// offset:5 — the match must start at or after byte 5. BEGIN is at 5.
	rs, _ := suricata.ParseRuleset(strings.NewReader(
		`alert tcp any any -> any any (content:"BEGIN"; offset:5; sid:20;)`))
	if len(rs.Match(body, "tcp")) != 1 {
		t.Error("offset:5 did not match a pattern starting at byte 5")
	}
	rs, _ = suricata.ParseRuleset(strings.NewReader(
		`alert tcp any any -> any any (content:"AAAAA"; offset:5; sid:21;)`))
	if len(rs.Match(body, "tcp")) != 0 {
		t.Error("offset:5 matched a pattern that starts at byte 0")
	}

	// within:4 — SECRET starts 4 bytes after BEGIN ends; within:3 is too tight.
	rs, _ = suricata.ParseRuleset(strings.NewReader(
		`alert tcp any any -> any any (content:"BEGIN"; content:"SECRET"; within:4; sid:22;)`))
	if len(rs.Match(body, "tcp")) != 1 {
		t.Error("within:4 did not match a pattern 4 bytes after the previous one")
	}
	rs, _ = suricata.ParseRuleset(strings.NewReader(
		`alert tcp any any -> any any (content:"BEGIN"; content:"SECRET"; within:2; sid:23;)`))
	if len(rs.Match(body, "tcp")) != 0 {
		t.Error("within:2 matched a pattern 4 bytes away — the window bounds where the match may START")
	}

	// distance:6 — SECRET is only 4 bytes past BEGIN, so it is too close.
	rs, _ = suricata.ParseRuleset(strings.NewReader(
		`alert tcp any any -> any any (content:"BEGIN"; content:"SECRET"; distance:6; sid:24;)`))
	if len(rs.Match(body, "tcp")) != 0 {
		t.Error("distance:6 matched a pattern only 4 bytes past the previous match")
	}
}

// A NEGATED CONTENT IS AN ABSENCE REQUIREMENT, and it does not advance the cursor.
//
// Mutation (treat a negated content as a normal one, or let it move the cursor): the rule below fires on
// the body containing the forbidden bytes → FAIL.
func TestANegatedContentRequiresAbsence(t *testing.T) {
	rs, _ := suricata.ParseRuleset(strings.NewReader(
		`alert tcp any any -> any any (content:"upload"; content:!"authorized"; sid:30;)`))

	if len(rs.Match([]byte("upload of a file"), "tcp")) != 1 {
		t.Error("the rule did not fire on a body missing the forbidden content")
	}
	if hits := rs.Match([]byte("upload of an authorized file"), "tcp"); len(hits) != 0 {
		t.Fatalf("the rule fired on a body CONTAINING the forbidden content (%+v) — content:! is an "+
			"absence requirement", hits)
	}
}

// PROTOCOL SCOPING IS HONOURED, and a flow with no recorded protocol does not satisfy a scoped rule.
//
// Matching a tcp rule against a flow nobody claimed was tcp would attribute the hit to a protocol that
// was never observed.
func TestProtocolScopingIsHonoured(t *testing.T) {
	rs, _ := suricata.ParseRuleset(strings.NewReader(
		`alert udp any any -> any any (content:"x"; sid:40;)` + "\n" +
			`alert ip any any -> any any (content:"x"; sid:41;)`))

	if hits := rs.Match([]byte("xx"), "udp"); len(hits) != 2 {
		t.Fatalf("udp flow matched %d rules, want both the udp and the ip one", len(hits))
	}
	hits := rs.Match([]byte("xx"), "tcp")
	if len(hits) != 1 || hits[0].SID != "41" {
		t.Fatalf("tcp flow matched %+v, want only the ip-scoped rule", hits)
	}
	if hits := rs.Match([]byte("xx"), ""); len(hits) != 1 || hits[0].SID != "41" {
		t.Fatalf("a flow with no recorded protocol matched %+v — a protocol-scoped rule firing on it "+
			"would attribute the hit to a protocol nobody observed", hits)
	}
}

// A SEMICOLON INSIDE A QUOTED MESSAGE DOES NOT SPLIT THE OPTIONS.
//
// Naive splitting breaks every rule whose msg contains one — which is a lot of them — and it breaks them
// by SHIFTING the remaining options, so the rule loads and means something else.
//
// Mutation (split on every semicolon): the sid is lost and the rule is refused, or worse, a modifier
// lands on the wrong content → FAIL.
func TestASemicolonInsideAMessageDoesNotSplitTheOptions(t *testing.T) {
	r, err := suricata.Parse(
		`alert tcp any any -> any any (msg:"ET TROJAN Bad; very bad"; content:"x"; sid:50;)`)
	if err != nil {
		t.Fatalf("a rule whose msg contains a semicolon was refused: %v", err)
	}
	if r.Msg != "ET TROJAN Bad; very bad" {
		t.Errorf("msg = %q, want the whole message", r.Msg)
	}
	if r.SID != "50" {
		t.Errorf("sid = %q — naive splitting shifts every later option, so the rule loads and means "+
			"something else", r.SID)
	}
}

// A REFUSED RULE DOES NOT FAIL THE WHOLE FILE, and every refusal is RECORDED.
//
// A community ruleset is thousands of rules from someone else; refusing the file because forty use
// flowbits would mean nobody ever loads one. What must not happen is a SILENT refusal — "which of my
// rules are actually running" has to be answerable after the load, not only at the moment it happened.
//
// Mutation (drop the Refused record, or abort the load on the first bad rule): the good rules are lost,
// or the refusals become invisible → FAIL.
func TestARefusedRuleIsRecordedAndTheRestStillLoad(t *testing.T) {
	file := strings.Join([]string{
		`# a community ruleset`,
		`alert tcp any any -> any any (msg:"good"; content:"aaa"; sid:100;)`,
		`alert http any any -> any any (msg:"scoped"; content:"bbb"; http.uri; sid:101;)`,
		`alert tcp any any -> any any (msg:"also good"; content:"ccc"; sid:102;)`,
	}, "\n")

	rs, err := suricata.ParseRuleset(strings.NewReader(file))
	if err != nil {
		t.Fatalf("the file failed to load because one rule was refused: %v — nobody would ever load a "+
			"community ruleset", err)
	}
	if rs.Size() != 2 {
		t.Fatalf("loaded %d rules, want the 2 that are honourable", rs.Size())
	}
	if len(rs.Refused) != 1 {
		t.Fatalf("recorded %d refusals, want 1 — a silent refusal means an operator cannot answer "+
			"'which of my rules are actually running'", len(rs.Refused))
	}
	ref := rs.Refused[0]
	if ref.SID != "101" || ref.Line != 3 || !strings.Contains(ref.Reason, "http.uri") {
		t.Errorf("the refusal does not identify the rule and the reason: %+v — an operator needs the "+
			"line they must look at, not a count", ref)
	}
}

// The supported set is enumerable, so an operator can be told what this engine speaks rather than
// discovering it one refused rule at a time.
func TestTheSupportedKeywordSetIsEnumerable(t *testing.T) {
	got := suricata.Supported()
	if len(got) < 8 {
		t.Fatalf("the supported set has %d keywords, which is fewer than this engine implements", len(got))
	}
	want := map[string]bool{"content": true, "sid": true, "depth": true, "within": true, "nocase": true}
	for _, k := range got {
		delete(want, k)
	}
	if len(want) > 0 {
		t.Errorf("the enumerated set omits keywords this engine honours: %v", want)
	}
}

// FuzzParse drives the parser with arbitrary rule text. It reads operator- and vendor-supplied files, so
// the property is total: any input parses or is refused, never a panic.
func FuzzParse(f *testing.F) {
	f.Add(`alert tcp any any -> any any (msg:"x"; content:"y"; sid:1;)`)
	f.Add(`alert tcp any any -> any any (content:"|4d 5a|"; depth:4; sid:2;)`)
	f.Add(`alert tcp any any -> any any (content:!"a"; within:3; sid:3;)`)
	f.Add(`(`)
	f.Fuzz(func(t *testing.T, in string) {
		r, err := suricata.Parse(in)
		if err != nil {
			return
		}
		if r.SID == "" {
			t.Fatalf("parsed a rule with no sid: %q", in)
		}
		if len(r.Contents) == 0 {
			t.Fatalf("parsed a rule with no content — it would match every flow: %q", in)
		}
		rs, perr := suricata.ParseRuleset(strings.NewReader(in))
		if perr != nil {
			return
		}
		_ = rs.Match([]byte("some body bytes"), "tcp")
	})
}
