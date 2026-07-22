package nips

import (
	"strings"
	"testing"
)

func mustFeed(t *testing.T, body string) *Feed {
	t.Helper()
	f, err := ParseFeed(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseFeed: %v", err)
	}
	return f
}

func TestDomainMatch(t *testing.T) {
	f := mustFeed(t, "domain evil.com\ndomain bad.example.org\n")
	cases := map[string]bool{
		"evil.com":        true,
		"c2.evil.com":     true, // parent-suffix
		"a.b.evil.com":    true,
		"evil.com:443":    true, // port stripped
		"notevil.com":     false,
		"evil.com.co":     false, // not a suffix match
		"example.org":     false, // only bad.example.org listed
		"bad.example.org": true,
	}
	for host, want := range cases {
		got := len(f.Match(host, "", "")) > 0
		if got != want {
			t.Errorf("Match(%q) domain = %v, want %v", host, got, want)
		}
	}
}

func TestIPMatch(t *testing.T) {
	f := mustFeed(t, "ip 1.2.3.4\ncidr 10.0.0.0/8\n")
	cases := map[string]bool{
		"1.2.3.4":  true,
		"1.2.3.5":  false,
		"10.9.9.9": true, // in CIDR
		"11.0.0.1": false,
		"":         false,
	}
	for ip, want := range cases {
		got := len(f.Match("", ip, "")) > 0
		if got != want {
			t.Errorf("Match(ip=%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestURIMatch(t *testing.T) {
	f := mustFeed(t, "uri /malware.exe\nuri /c2/beacon\n")
	if len(f.Match("", "", "/downloads/malware.exe")) == 0 {
		t.Error("expected a URI match on /malware.exe substring")
	}
	if len(f.Match("", "", "/safe/path")) != 0 {
		t.Error("expected no URI match on a clean path")
	}
}

func TestEmptyFeedMatchesNothing(t *testing.T) {
	f := mustFeed(t, "# just a comment\n\n")
	if len(f.Match("evil.com", "1.2.3.4", "/malware.exe")) != 0 {
		t.Error("an empty feed should match nothing")
	}
	var nilFeed *Feed
	if len(nilFeed.Match("evil.com", "1.2.3.4", "/x")) != 0 {
		t.Error("a nil feed should match nothing")
	}
}

func TestMatchCategoriesAndConfidence(t *testing.T) {
	f := mustFeed(t, "domain evil.com\nip 1.2.3.4\nuri /beacon\n")
	got := f.Match("evil.com", "1.2.3.4", "/beacon")
	if len(got) != 3 {
		t.Fatalf("want 3 matches (domain+ip+uri), got %d", len(got))
	}
	seen := map[Category]bool{}
	for _, m := range got {
		seen[m.Category] = true
		if m.Confidence != 1.0 {
			t.Errorf("IOC match confidence = %v, want 1.0 (definitive)", m.Confidence)
		}
	}
	for _, c := range []Category{CategoryDomain, CategoryIP, CategoryURI} {
		if !seen[c] {
			t.Errorf("missing category %v", c)
		}
	}
}

func TestLoadFeedRejectsMalformed(t *testing.T) {
	bad := []string{
		"garbage line with three fields here",
		"onlyonefield",
		"ip not-an-ip",
		"cidr 10.0.0.0/999",
		"unknownkind foo",
	}
	for _, b := range bad {
		if _, err := ParseFeed(strings.NewReader(b)); err == nil {
			t.Errorf("ParseFeed(%q) should error", b)
		}
	}
}
