package signature

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, text string) *Ruleset {
	t.Helper()
	rs, err := ParseRuleset(strings.NewReader(text))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return rs
}

// hitIDs returns the rule ids of the matches, for assertions.
func hitIDs(hits []Hit) []string {
	out := make([]string, len(hits))
	for i, h := range hits {
		out[i] = h.RuleID
	}
	return out
}

func TestMatchLiteralContent(t *testing.T) {
	rs := mustParse(t, "rule shell\ncontent /bin/sh -c\nend\n")
	if got := hitIDs(rs.Match([]byte("run /bin/sh -c 'id'"))); len(got) != 1 || got[0] != "shell" {
		t.Fatalf("literal match = %v, want [shell]", got)
	}
	if got := rs.Match([]byte("nothing bad here")); got != nil {
		t.Fatalf("clean body matched %v, want nil", got)
	}
}

func TestMatchNocase(t *testing.T) {
	rs := mustParse(t, "rule beacon\ncontent X-Beacon:\nnocase\nend\n")
	if got := rs.Match([]byte("header x-BEACON: 1")); len(got) != 1 {
		t.Fatalf("nocase should match case-insensitively, got %v", got)
	}
	// Without nocase the same rule is case-sensitive.
	cs := mustParse(t, "rule beacon\ncontent X-Beacon:\nend\n")
	if got := cs.Match([]byte("header x-beacon: 1")); got != nil {
		t.Fatalf("case-sensitive rule matched a different case: %v", got)
	}
}

func TestMatchRegex(t *testing.T) {
	rs := mustParse(t, `rule sqli
regex (?i)union\s+select
end
`)
	if got := rs.Match([]byte("a=1 UNION   SELECT password")); len(got) != 1 {
		t.Fatalf("regex should match, got %v", got)
	}
	if got := rs.Match([]byte("union of sets")); got != nil {
		t.Fatalf("regex false positive: %v", got)
	}
}

// A rule with several matchers is AND: every content AND the regex must be present.
func TestMatchMultiPatternAND(t *testing.T) {
	rs := mustParse(t, `rule combo
content EXEC
content payload
regex \d{4}
end
`)
	if got := rs.Match([]byte("EXEC the payload 1234")); len(got) != 1 {
		t.Fatalf("all three present should match, got %v", got)
	}
	// Missing one literal → no match (AND, not OR).
	if got := rs.Match([]byte("EXEC 1234")); got != nil {
		t.Fatalf("one literal missing must not match (AND semantics), got %v", got)
	}
	// Missing the regex → no match.
	if got := rs.Match([]byte("EXEC the payload")); got != nil {
		t.Fatalf("regex missing must not match, got %v", got)
	}
}

// The scan is bounded: a pattern that appears only PAST the budget is not matched, and
// a huge body does not hang. This is the DoS-safety property.
func TestScanIsBounded(t *testing.T) {
	rs := mustParse(t, "rule tail\ncontent NEEDLE\nend\n")
	rs.maxScan = 16 // tiny budget for the test
	body := append([]byte(strings.Repeat("a", 100)), []byte("NEEDLE")...)
	if got := rs.Match(body); got != nil {
		t.Fatalf("a pattern past the scan budget must not match, got %v", got)
	}
	// The same pattern WITHIN the budget matches.
	rs.maxScan = 200
	if got := rs.Match(body); len(got) != 1 {
		t.Fatalf("a pattern within the budget should match, got %v", got)
	}
}

// The no-content boundary: a Hit carries the rule id but never the matched substring.
func TestHitCarriesNoMatchedBytes(t *testing.T) {
	rs := mustParse(t, "rule secret\ncontent TOPSECRETPAYLOAD\nend\n")
	hits := rs.Match([]byte("... TOPSECRETPAYLOAD ..."))
	if len(hits) != 1 {
		t.Fatal("expected a hit")
	}
	if hits[0].RuleID != "secret" {
		t.Fatalf("rule id = %q, want secret", hits[0].RuleID)
	}
	if strings.Contains(hits[0].RuleID, "TOPSECRETPAYLOAD") {
		t.Fatal("the Hit leaked the matched bytes into the rule id")
	}
}

func TestEmptyRulesetIsInert(t *testing.T) {
	rs := mustParse(t, "# only a comment\n\n")
	if !rs.Empty() || rs.Match([]byte("anything")) != nil {
		t.Fatal("an empty ruleset must match nothing")
	}
	var nilRS *Ruleset
	if !nilRS.Empty() || nilRS.Match([]byte("x")) != nil {
		t.Fatal("a nil ruleset must be inert")
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"rule without end":     "rule r\ncontent x\n",
		"rule without matcher": "rule r\nend\n",
		"content outside rule": "content x\n",
		"nested rule":          "rule a\nrule b\nend\n",
		"end outside rule":     "end\n",
		"bad confidence":       "rule r\nconfidence 9\ncontent x\nend\n",
		"empty content":        "rule r\ncontent \nend\n",
		"two regexes":          "rule r\nregex a\nregex b\nend\n",
		"bad regex":            "rule r\nregex [\nend\n",
		"unknown directive":    "rule r\nfoo bar\nend\n",
		"rule without id":      "rule \ncontent x\nend\n",
	}
	for name, text := range cases {
		if _, err := ParseRuleset(strings.NewReader(text)); err == nil {
			t.Errorf("%s: expected a parse error, got nil", name)
		}
	}
}

// The watcher reads its baseline SYNCHRONOUSLY at construction, so a rule added right
// after start is observed as a change and reloaded — no async-baseline race.
func TestRulesetWatcherReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(path, []byte("rule a\ncontent AAA\nend\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := NewRulesetWatcher(path) // baseline captured HERE, synchronously

	loaded := make(chan *Ruleset, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Watch(ctx, 20*time.Millisecond, func(rs *Ruleset) { loaded <- rs }, func(err error) { t.Error(err) })

	// Overwrite with an added rule and a fresh mtime.
	time.Sleep(30 * time.Millisecond)
	if err := os.WriteFile(path, []byte("rule a\ncontent AAA\nend\nrule b\ncontent BBB\nend\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	touchFuture(t, path)

	select {
	case rs := <-loaded:
		if rs.Size() != 2 {
			t.Fatalf("reloaded ruleset has %d rules, want 2", rs.Size())
		}
		if got := rs.Match([]byte("has BBB")); len(got) != 1 || got[0].RuleID != "b" {
			t.Fatalf("the newly-added rule did not take effect: %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher never reloaded the changed ruleset")
	}
}

// A malformed edit is served-stale: onErr fires and the watcher keeps going (never
// applies the broken version).
func TestRulesetWatcherServesStaleOnBadEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(path, []byte("rule a\ncontent AAA\nend\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := NewRulesetWatcher(path)
	gotErr := make(chan error, 4)
	applied := make(chan *Ruleset, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Watch(ctx, 20*time.Millisecond, func(rs *Ruleset) { applied <- rs }, func(err error) { gotErr <- err })

	time.Sleep(30 * time.Millisecond)
	if err := os.WriteFile(path, []byte("rule broken\n"), 0o600); err != nil { // no 'end'
		t.Fatal(err)
	}
	touchFuture(t, path)

	select {
	case <-gotErr: // reported the bad edit
	case rs := <-applied:
		t.Fatalf("applied a malformed ruleset (%d rules) — must serve stale", rs.Size())
	case <-time.After(2 * time.Second):
		t.Fatal("watcher neither reported nor applied the bad edit")
	}
}

// touchFuture bumps the file mtime forward so a same-second rewrite is still seen as a
// change (mtime resolution can be coarse).
func touchFuture(t *testing.T, path string) {
	t.Helper()
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}
