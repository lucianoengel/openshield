package rfc5424_test

import (
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/connectors/rfc5424"
)

// SIEM-9: modern syslog. The structured-data half is what earns it a place next to CEF — an SD element
// and a CEF extension become the same searchable key/value, so an analyst hunts once across both.

const sample = `<165>1 2026-07-26T14:05:09.123Z fw01.corp sshd 4321 SESSION ` +
	`[auth@32473 user="alice" result="fail"][origin ip="203.0.113.9"] Failed password for alice`

func TestParsesAFullMessage(t *testing.T) {
	m, err := rfc5424.Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	// PRI is split once, here, so three call sites cannot divide it three ways.
	if m.Priority != 165 || m.Facility != 20 || m.Severity != 5 {
		t.Errorf("pri=%d facility=%d severity=%d, want 165/20/5", m.Priority, m.Facility, m.Severity)
	}
	if rfc5424.SeverityName(m.Severity) != "notice" {
		t.Errorf("severity name = %q, want notice", rfc5424.SeverityName(m.Severity))
	}
	if m.Hostname != "fw01.corp" || m.AppName != "sshd" || m.ProcID != "4321" || m.MsgID != "SESSION" {
		t.Errorf("header = %+v", m)
	}
	if m.Timestamp.IsZero() || m.Timestamp.Year() != 2026 {
		t.Errorf("timestamp = %v", m.Timestamp)
	}
	if m.Message != "Failed password for alice" {
		t.Errorf("message = %q", m.Message)
	}
	// Flattened to sdid.key, because the destination is a flat JSONB map an analyst queries directly.
	for k, want := range map[string]string{
		"auth@32473.user": "alice", "auth@32473.result": "fail", "origin.ip": "203.0.113.9",
	} {
		if m.StructuredData[k] != want {
			t.Errorf("structured data %q = %q, want %q", k, m.StructuredData[k], want)
		}
	}
}

// TestEscapesInsideStructuredValues is why this is hand-parsed rather than regexed: a value may contain a
// quoted bracket, and a naive parser truncates it there — silently, and only for the messages that have
// one.
//
// Mutation: stop honouring `\]` (or `\"`) → the value truncates → FAILS.
func TestEscapesInsideStructuredValues(t *testing.T) {
	line := `<13>1 - - - - - [x note="a \"quoted\" and \] bracket \\ slash"] body`
	m, err := rfc5424.Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	got := m.StructuredData["x.note"]
	want := `a "quoted" and ] bracket \ slash`
	if got != want {
		t.Errorf("value = %q, want %q — an escaped bracket must not end the element", got, want)
	}
	if m.Message != "body" {
		t.Errorf("message = %q, want body — the parser lost track of where the element ended", m.Message)
	}
}

// TestNilValuesDecodeToEmpty: "-" means ABSENT, and decoding it here means no consumer has to know that
// a hyphen is special in this format while being a legitimate value elsewhere.
func TestNilValuesDecodeToEmpty(t *testing.T) {
	m, err := rfc5424.Parse(`<0>1 - - - - - - just a message`)
	if err != nil {
		t.Fatal(err)
	}
	if m.Hostname != "" || m.AppName != "" || m.ProcID != "" || m.MsgID != "" {
		t.Errorf("nil values were not decoded to empty: %+v", m)
	}
	if !m.Timestamp.IsZero() {
		t.Errorf("a nil timestamp became %v", m.Timestamp)
	}
	if m.Message != "just a message" {
		t.Errorf("message = %q", m.Message)
	}
}

// TestMalformedIsAnErrorNotAPartialRecord — a log ingest that quietly mangles lines is a blind spot that
// looks like coverage (D17).
func TestMalformedIsAnErrorNotAPartialRecord(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"no PRI", `1 2026-07-26T14:05:09Z h a p m - body`},
		{"unterminated PRI", `<165 1 ...`},
		{"priority out of range", `<999>1 - - - - - body`},
		{"non-numeric priority", `<abc>1 - - - - - body`},
		{"unsupported version", `<13>2 - - - - - body`},
		{"truncated header", `<13>1 - -`},
		{"bad timestamp", `<13>1 not-a-time h a p m - body`},
		{"unterminated element", `<13>1 - - - - - [x k="v"`},
		{"unquoted value", `<13>1 - - - - - [x k=v] body`},
		{"param without =", `<13>1 - - - - - [x k] body`},
		{"element with no id", `<13>1 - - - - - [ k="v"] body`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rfc5424.Parse(tc.line); err == nil {
				t.Errorf("%s parsed without error — a malformed line must never become a partial record "+
					"treated as complete", tc.name)
			}
		})
	}
	// And an oversized line is refused rather than buffered: a device sending megabytes is an exhaustion
	// vector, not a log.
	if _, err := rfc5424.Parse("<13>1 - - - - - " + strings.Repeat("x", 70<<10)); err == nil {
		t.Error("an oversized line was accepted")
	}
}
