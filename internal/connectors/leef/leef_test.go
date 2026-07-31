package leef_test

import (
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/connectors/leef"
)

// SIEM-16 — LEEF.
//
// Where an ArcSight estate emits CEF, a QRadar one emits LEEF, and an estate that has bought from both
// emits both. A deployment that reads one and not the other is not covering "most of the estate" — it is
// covering whichever half of it was bought first.

// THE HEADLINE: a LEEF 1.0 record parses, with its TAB-separated attributes.
func TestALeef1RecordParsesWithTabSeparatedAttributes(t *testing.T) {
	line := "LEEF:1.0|Lancope|StealthWatch|1.0|41|" +
		strings.Join([]string{"src=192.0.2.1", "dst=10.0.0.5", "usrName=alice", "sev=5"}, "\t")

	m, err := leef.Parse([]byte(line))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if m.Version != "1.0" || m.Vendor != "Lancope" || m.Product != "StealthWatch" || m.EventID != "41" {
		t.Fatalf("header not parsed: %+v", m)
	}
	for k, want := range map[string]string{
		"src": "192.0.2.1", "dst": "10.0.0.5", "usrName": "alice", "sev": "5",
	} {
		if m.Attributes[k] != want {
			t.Errorf("attribute %q = %q, want %q", k, m.Attributes[k], want)
		}
	}
}

// THE DELIMITER IS THE WHOLE FEATURE.
//
// A parser that assumes tab does not FAIL on a LEEF 2.0 record using `^` — it succeeds, producing one
// enormous key nobody will ever search for. Every event from that appliance is then stored, counted as
// ingested, and invisible to every hunt.
//
// Mutation (ignore the 2.0 delimiter field and always split on tab): the whole attribute section becomes
// a single key → FAIL.
func TestALeef2CustomDelimiterIsHonoured(t *testing.T) {
	for _, tc := range []struct{ name, field, sep string }{
		{"literal caret", "^", "^"},
		{"literal pipe-ish char", "~", "~"},
		{"hex x09", "x09", "\t"},
		{"hex 0x09", "0x09", "\t"},
		{"backslash x5e", `\x5e`, "^"},
		{"empty means default", "", "\t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := "LEEF:2.0|Acme|Firewall|2.1|4711|" + tc.field + "|" +
				strings.Join([]string{"src=192.0.2.1", "dst=10.0.0.5", "usrName=alice"}, tc.sep)

			m, err := leef.Parse([]byte(line))
			if err != nil {
				t.Fatalf("parsing: %v", err)
			}
			if m.Delimiter != tc.sep {
				t.Errorf("resolved delimiter = %q, want %q", m.Delimiter, tc.sep)
			}
			if len(m.Attributes) != 3 {
				t.Fatalf("got %d attributes, want 3 — a record split on the WRONG delimiter does not "+
					"fail, it collapses into one enormous key that is stored, counted as ingested, and "+
					"invisible to every hunt: %v", len(m.Attributes), m.Attributes)
			}
			if m.Attributes["usrName"] != "alice" {
				t.Errorf("usrName = %q, want alice", m.Attributes["usrName"])
			}
		})
	}
}

// AN UNRECOGNISED DELIMITER IS REFUSED, not defaulted.
//
// Falling back to tab would parse the record with the wrong separator — the exact silent failure above.
// A refused line is counted as dropped and an operator can see it; a mis-parsed one cannot be seen at
// all.
//
// Mutation (return the default instead of an error): the line parses into one key → FAIL.
func TestAnUnrecognisedDelimiterIsRefusedRatherThanDefaulted(t *testing.T) {
	line := "LEEF:2.0|Acme|Firewall|2.1|4711|NOTADELIM|src=192.0.2.1\tdst=10.0.0.5"
	if _, err := leef.Parse([]byte(line)); err == nil {
		t.Fatal("an unrecognised delimiter field was accepted — the record would be split on the wrong " +
			"separator, stored, counted as ingested, and invisible to every hunt. A refused line at " +
			"least appears in the drop counter")
	}
}

// A PIPE INSIDE A HEADER FIELD DOES NOT SHIFT THE REST.
//
// A vendor or product name containing an escaped pipe is legal. Splitting naively shifts every later
// field — silently, and only for that vendor, so the estate sees one appliance's events attributed to
// the wrong product and nothing anywhere reports a problem.
//
// Mutation (split on every pipe rather than unescaped ones): the product and version shift → FAIL.
func TestAnEscapedPipeInAHeaderDoesNotShiftTheFields(t *testing.T) {
	m, err := leef.Parse([]byte(`LEEF:1.0|Acme\|Corp|Firewall|2.1|4711|src=192.0.2.1`))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if m.Vendor != "Acme|Corp" {
		t.Errorf("vendor = %q, want %q", m.Vendor, "Acme|Corp")
	}
	if m.Product != "Firewall" || m.DeviceVersion != "2.1" || m.EventID != "4711" {
		t.Fatalf("an escaped pipe shifted the later header fields: %+v — the estate would see this "+
			"appliance's events attributed to the wrong product, and nothing would report it", m)
	}
}

// A VALUE MAY CONTAIN A PIPE. The version, not a pipe count, distinguishes 1.0 from 2.0 — precisely so
// that a record carrying a URL is not mis-split.
func TestAValueContainingAPipeIsNotMistakenForAHeaderBoundary(t *testing.T) {
	m, err := leef.Parse([]byte("LEEF:1.0|Acme|Firewall|2.1|4711|request=https://x/a|b\tsrc=192.0.2.1"))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if m.Attributes["request"] != "https://x/a|b" {
		t.Errorf("request = %q, want the whole URL — counting pipes would mis-split exactly the records "+
			"that carry one", m.Attributes["request"])
	}
	if m.Attributes["src"] != "192.0.2.1" {
		t.Errorf("the attribute after the pipe-bearing value was lost: %v", m.Attributes)
	}
}

// STRUCTURALLY BAD LINES ARE REFUSED, never a partial record silently treated as complete.
func TestMalformedLinesAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"empty", ""},
		{"no prefix", "CEF:0|Acme|Firewall|2.1|4711|5|src=1.2.3.4"},
		{"too few headers", "LEEF:1.0|Acme|Firewall|"},
		{"no version", "LEEF:|Acme|Firewall|2.1|4711|src=1.2.3.4"},
		{"2.0 with no delimiter field", "LEEF:2.0|Acme|Firewall|2.1|4711"},
		{"oversized", "LEEF:1.0|Acme|Firewall|2.1|4711|src=" + strings.Repeat("x", 70<<10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := leef.Parse([]byte(tc.line)); err == nil {
				t.Fatalf("accepted a malformed line: %q", tc.line)
			}
		})
	}
}

// A FRAGMENT WITH NO '=' IS SKIPPED, not stored under an empty key — an empty key is unsearchable, and
// two such fragments would collide and overwrite each other.
func TestAFragmentWithNoEqualsIsSkipped(t *testing.T) {
	m, err := leef.Parse([]byte("LEEF:1.0|Acme|Firewall|2.1|4711|src=1.2.3.4\tgarbage\tdst=5.6.7.8"))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if _, present := m.Attributes[""]; present {
		t.Fatal("a fragment with no '=' was stored under an empty key — it is unsearchable, and a " +
			"second such fragment would silently overwrite it")
	}
	if m.Attributes["src"] != "1.2.3.4" || m.Attributes["dst"] != "5.6.7.8" {
		t.Fatalf("the attributes either side of the bad fragment were lost: %v", m.Attributes)
	}
}

// FuzzParse drives the parser with arbitrary bytes. It reads whatever an estate's appliances send, so the
// property is total: for ANY input it returns a record or an error, never a panic.
func FuzzParse(f *testing.F) {
	f.Add([]byte("LEEF:1.0|Acme|Firewall|2.1|4711|src=1.2.3.4\tdst=5.6.7.8"))
	f.Add([]byte("LEEF:2.0|Acme|Firewall|2.1|4711|^|src=1.2.3.4^dst=5.6.7.8"))
	f.Add([]byte("LEEF:2.0|A|B|C|D|x09|k=v"))
	f.Add([]byte("LEEF:"))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := leef.Parse(b)
		if err != nil {
			return
		}
		if m.Delimiter == "" {
			t.Fatalf("parsed with an EMPTY delimiter — strings.Split on it splits between every "+
				"character, so the attribute map is one entry per byte: %q", string(b))
		}
		for k := range m.Attributes {
			if k == "" {
				t.Fatalf("an empty attribute key survived: %q", string(b))
			}
		}
	})
}
