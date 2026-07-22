package cef

import "testing"

// TestFromSyslogExtractsCEF (SIEM-4): a CEF payload carried in a syslog message's free text is found
// and parsed into its fields.
func TestFromSyslogExtractsCEF(t *testing.T) {
	// What syslog.Parse yields as Msg after stripping the <PRI>/timestamp/host header: the CEF payload,
	// possibly with a leading device tag before the marker.
	line := `fw01 CEF:0|Acme|Firewall|1.2|100|Worm blocked|8|src=10.0.0.1 dst=10.0.0.2 msg=worm stopped by rule 42`
	m, ok := FromSyslog(line)
	if !ok {
		t.Fatal("FromSyslog did not find a CEF payload in a CEF-over-syslog line")
	}
	if m.Vendor != "Acme" || m.Product != "Firewall" || m.SignatureID != "100" || m.Name != "Worm blocked" || m.Severity != "8" {
		t.Fatalf("wrong CEF headers: %+v", m)
	}
	if m.Extensions["src"] != "10.0.0.1" || m.Extensions["msg"] != "worm stopped by rule 42" {
		t.Fatalf("wrong CEF extensions: %+v", m.Extensions)
	}
}

// TestFromSyslogSkipsNonCEF (SIEM-4): a plain syslog line (no CEF payload) and a present-but-malformed
// CEF payload are both reported as "no CEF" — a routine skip, not an error, so a mixed stream is fine.
func TestFromSyslogSkipsNonCEF(t *testing.T) {
	for _, line := range []string{
		"sshd[123]: Accepted password for alice from 10.0.0.9",
		"just some free text with no marker",
		"",
		"CEF:0|only|three|headers", // has the marker but too few headers → parse fails → skip
	} {
		if m, ok := FromSyslog(line); ok {
			t.Errorf("FromSyslog(%q) reported CEF where there is none: %+v", line, m)
		}
	}
}
