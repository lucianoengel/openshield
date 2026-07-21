package syslog_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/connectors/syslog"
)

func TestParse5424(t *testing.T) {
	// PRI 34 = facility 4 (auth), severity 2 (critical).
	line := `<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - failed login for user root`
	m, err := syslog.Parse([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if m.Facility != 4 || m.Severity != 2 {
		t.Errorf("facility/severity = %d/%d, want 4/2", m.Facility, m.Severity)
	}
	if m.Host != "mymachine.example.com" {
		t.Errorf("host = %q", m.Host)
	}
	if m.App != "su" {
		t.Errorf("app = %q, want su", m.App)
	}
	if m.Msg != "failed login for user root" {
		t.Errorf("msg = %q", m.Msg)
	}
	if m.Timestamp.IsZero() {
		t.Error("5424 timestamp not parsed")
	}
}

// RFC 5424 with real STRUCTURED-DATA (containing spaces inside the brackets) — the SD must
// be skipped so MSG is the free text, not the bracketed data.
func TestParse5424StructuredData(t *testing.T) {
	line := `<165>1 2003-10-11T22:14:15.003Z host evntslog - ID47 [exampleSDID@32473 iut="3" eventID="1011"] BOM an application event`
	m, err := syslog.Parse([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if m.Msg != "BOM an application event" {
		t.Errorf("msg = %q, want the text after the structured data", m.Msg)
	}
	if m.App != "evntslog" {
		t.Errorf("app = %q", m.App)
	}
}

func TestParse3164(t *testing.T) {
	// PRI 13 = facility 1 (user), severity 5 (notice).
	line := `<13>Feb  5 17:32:18 10.0.0.99 myapp: user alice exported a report`
	m, err := syslog.Parse([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if m.Facility != 1 || m.Severity != 5 {
		t.Errorf("facility/severity = %d/%d, want 1/5", m.Facility, m.Severity)
	}
	if m.Host != "10.0.0.99" {
		t.Errorf("host = %q", m.Host)
	}
	if m.App != "myapp" {
		t.Errorf("app = %q, want myapp", m.App)
	}
	if m.Msg != "user alice exported a report" {
		t.Errorf("msg = %q", m.Msg)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"no priority":      "Feb  5 17:32:18 host app: msg",
		"no opening <":     "34>1 host app - - msg", // has '>' but no leading '<'
		"unclosed pri":     "<34 1 ...",
		"non-numeric pri":  "<xy>1 ...",
		"pri out of range": "<999>1 ...",
	}
	for name, line := range cases {
		if _, err := syslog.Parse([]byte(line)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

// The priority split is exact across the range: PRI = facility*8 + severity.
func TestPriorityDecoding(t *testing.T) {
	for _, tc := range []struct {
		pri           int
		facility, sev int
	}{
		{0, 0, 0},    // kernel / emergency
		{191, 23, 7}, // local7 / debug (the max)
		{86, 10, 6},  // authpriv / info
	} {
		line := "<" + itoa(tc.pri) + ">1 - - - - - -"
		m, err := syslog.Parse([]byte(line))
		if err != nil {
			t.Fatalf("pri %d: %v", tc.pri, err)
		}
		if m.Facility != tc.facility || m.Severity != tc.sev {
			t.Errorf("pri %d → %d/%d, want %d/%d", tc.pri, m.Facility, m.Severity, tc.facility, tc.sev)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
