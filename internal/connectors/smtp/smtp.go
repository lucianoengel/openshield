// Package smtp is an SMTP-message connector (Phase C — email breadth). It parses an SMTP
// session transcript into its envelope (MAIL FROM / RCPT TO) and message body, so outbound
// email enters the SAME pipeline as file, HTTP, and DNS events — the body is classified
// (PII/secrets in an email or its inline content) and the envelope is metadata for policy.
//
// Like the DNS and gateway connectors it is a pure parser + Event producer: no sockets, so
// the wire-transcript surface (untrusted bytes) is tested in ordinary Go. The message BODY
// is returned for the sandboxed worker to classify (D72) — it is NOT placed in the Event
// (D10/D29); only envelope METADATA (the recipient domains) rides the Event, and even the
// full addresses are kept out of the Event to avoid leaking them (a domain is the
// destination, an address is PII).
package smtp

import (
	"bytes"
	"fmt"
	"strings"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Message is the parsed content of one SMTP session.
type Message struct {
	From    string   // envelope MAIL FROM address (host-only, for policy/audit)
	To      []string // envelope RCPT TO addresses
	Subject string   // the Subject header, if present (metadata)
	Body    []byte   // the DATA payload (headers + body), for classification
}

// maxMessage bounds the DATA payload the connector will buffer. A live gateway also
// bounds the socket read; this bounds the parse so a session cannot exhaust memory.
const maxMessage = 32 << 20 // 32 MiB

// ParseSession parses an SMTP client transcript (the command lines the client sent,
// including the DATA payload). It extracts the envelope and the message. A session with no
// sender, no recipient, or an unterminated DATA block is an error — never a partial
// message silently treated as complete (D17). Lines may end CRLF or LF.
func ParseSession(transcript []byte) (*Message, error) {
	if len(transcript) > maxMessage {
		return nil, fmt.Errorf("smtp: session exceeds %d bytes", maxMessage)
	}
	lines := splitLines(transcript)
	m := &Message{}
	inData := false
	dataTerminated := false
	var data [][]byte

	for _, line := range lines {
		if inData {
			// The DATA block ends at a line containing only ".".
			if string(line) == "." {
				inData = false
				dataTerminated = true
				continue
			}
			// Un-dot-stuff: a line the client sent starting with ".." is a literal ".".
			if len(line) >= 1 && line[0] == '.' {
				line = line[1:]
			}
			data = append(data, line)
			continue
		}
		upper := strings.ToUpper(strings.TrimSpace(string(line)))
		switch {
		case strings.HasPrefix(upper, "MAIL FROM:"):
			m.From = extractAddr(string(line)[len("MAIL FROM:"):])
		case strings.HasPrefix(upper, "RCPT TO:"):
			if a := extractAddr(string(line)[len("RCPT TO:"):]); a != "" {
				m.To = append(m.To, a)
			}
		case upper == "DATA":
			inData = true
		}
	}

	if m.From == "" {
		return nil, fmt.Errorf("smtp: no MAIL FROM in session")
	}
	if len(m.To) == 0 {
		return nil, fmt.Errorf("smtp: no RCPT TO in session")
	}
	if !dataTerminated {
		return nil, fmt.Errorf("smtp: DATA block missing or unterminated (no lone '.')")
	}
	m.Body = bytes.Join(data, []byte("\n"))
	m.Subject = extractSubject(data)
	return m, nil
}

// RecipientDomains returns the distinct domains of the recipients — the destination
// metadata a policy acts on (an egress rule allows/denies mail to a domain). Full
// addresses are deliberately NOT surfaced to the Event (they are PII).
func RecipientDomains(m *Message) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, addr := range m.To {
		if at := strings.LastIndexByte(addr, '@'); at >= 0 && at+1 < len(addr) {
			d := strings.ToLower(addr[at+1:])
			if _, ok := seen[d]; !ok {
				seen[d] = struct{}{}
				out = append(out, d)
			}
		}
	}
	return out
}

// ToEvent builds a NetworkSubject Event carrying envelope METADATA only. The primary
// recipient domain goes in sni_host (the destination); protocol tcp, dst_port 25. The
// message body is NOT in the Event — it is classified separately in the worker (D10/D29).
func ToEvent(flowID, srcIP string, m *Message) *corev1.Event {
	host := ""
	if d := RecipientDomains(m); len(d) > 0 {
		host = d[0]
	}
	return &corev1.Event{
		ConnectorId: "smtp",
		EventId:     "smtp-" + flowID,
		Kind:        corev1.EventKind_EVENT_KIND_SMTP_MESSAGE,
		Target: &corev1.Event_Network{Network: &corev1.NetworkSubject{
			FlowId:   flowID,
			SrcIp:    srcIP,
			DstPort:  25,
			Protocol: "tcp",
			SniHost:  host,
		}},
	}
}

// extractAddr pulls the address out of an SMTP path argument: "<a@b>" or "a@b" possibly
// followed by ESMTP parameters. Returns "" if none is found.
func extractAddr(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '<'); i >= 0 {
		if j := strings.IndexByte(s[i:], '>'); j > 0 {
			return strings.TrimSpace(s[i+1 : i+j])
		}
	}
	// No angle brackets: take the first whitespace-delimited token.
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// extractSubject reads the Subject header from the DATA lines (headers precede the first
// blank line). Metadata only — the body is classified, not the Subject.
func extractSubject(data [][]byte) string {
	for _, line := range data {
		if len(line) == 0 {
			return "" // reached the body without a Subject
		}
		if len(line) >= 8 && strings.EqualFold(string(line[:8]), "subject:") {
			return strings.TrimSpace(string(line[8:]))
		}
	}
	return ""
}

// splitLines splits on LF and trims a trailing CR, so CRLF and LF transcripts both work.
func splitLines(b []byte) [][]byte {
	raw := bytes.Split(b, []byte("\n"))
	out := make([][]byte, 0, len(raw))
	for _, l := range raw {
		out = append(out, bytes.TrimSuffix(l, []byte("\r")))
	}
	return out
}
