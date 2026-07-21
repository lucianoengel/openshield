// Package syslog is a third-party log-ingest connector (Phase F5). It parses RFC 5424 and
// RFC 3164 (BSD) syslog messages into structured records so OpenShield can ingest EXTERNAL
// logs — the step that makes it a SIEM consuming third-party sources, not only its own
// signed telemetry.
//
// Like the DNS and SMTP connectors it is a pure parser: the untrusted-bytes surface (a
// syslog line from any host) is handled here and tested in ordinary Go, separate from any
// socket. A malformed line is an error, never a partial record silently treated as
// complete (D17) — a log ingest that quietly drops or mangles lines is a blind spot.
package syslog

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Severity and Facility are the two halves of the syslog priority (PRI = facility*8 +
// severity). Severity 0 (emergency) .. 7 (debug); facility 0 (kernel) .. 23 (local7).
type Message struct {
	Facility  int
	Severity  int
	Timestamp time.Time // zero if the source omitted/!parseable
	Host      string
	App       string // APP-NAME (5424) or TAG (3164)
	Msg       string // the free-text message
}

// maxLine bounds a syslog line; a source that sends a multi-megabyte "line" is an
// exhaustion vector, not a log.
const maxLine = 64 << 10

// Parse decodes one syslog line (RFC 5424 preferred, RFC 3164 fallback). The leading
// "<PRI>" is required and validated (0..191); everything after is best-effort structured,
// but a message with no valid priority is rejected — the priority is the one field every
// syslog message has, and its absence means the input is not syslog.
func Parse(line []byte) (Message, error) {
	if len(line) == 0 {
		return Message{}, fmt.Errorf("syslog: empty line")
	}
	if len(line) > maxLine {
		return Message{}, fmt.Errorf("syslog: line exceeds %d bytes", maxLine)
	}
	s := string(line)
	pri, rest, err := parsePriority(s)
	if err != nil {
		return Message{}, err
	}
	m := Message{Facility: pri / 8, Severity: pri % 8}

	// RFC 5424 begins with a version digit immediately after the PRI: "<PRI>1 ...".
	if len(rest) > 0 && rest[0] == '1' && (len(rest) == 1 || rest[1] == ' ') {
		parse5424(rest, &m)
	} else {
		parse3164(rest, &m)
	}
	return m, nil
}

// parsePriority reads "<N>" from the front and returns N (0..191) and the remainder. A
// missing '<', a missing '>', a non-numeric or out-of-range value is an error.
func parsePriority(s string) (int, string, error) {
	if len(s) < 3 || s[0] != '<' {
		return 0, "", fmt.Errorf("syslog: missing priority")
	}
	end := strings.IndexByte(s, '>')
	if end < 2 || end > 4 {
		return 0, "", fmt.Errorf("syslog: malformed priority")
	}
	pri, err := strconv.Atoi(s[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return 0, "", fmt.Errorf("syslog: priority out of range")
	}
	return pri, s[end+1:], nil
}

// parse5424: "1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG". A "-" is the NIL value.
func parse5424(rest string, m *Message) {
	fields := strings.SplitN(rest, " ", 7)
	// fields[0] = "1" (version). Guard length as we go — a truncated header still yields
	// what was present rather than erroring (the PRI already validated it as syslog).
	get := func(i int) string {
		if i < len(fields) && fields[i] != "-" {
			return fields[i]
		}
		return ""
	}
	if ts := get(1); ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			m.Timestamp = t
		}
	}
	m.Host = get(2)
	m.App = get(3)
	// fields[4]=PROCID, fields[5]=MSGID, fields[6]="STRUCTURED-DATA MSG". Strip the
	// SD element(s) so MSG is the free text, not "- msg" or "[sd...] msg".
	if len(fields) >= 7 {
		m.Msg = stripStructuredData(fields[6])
	}
}

// stripStructuredData removes the leading SD field from "SD MSG". SD is "-" (NIL) or one
// or more "[...]" elements with no space between them, followed by a space and the message.
func stripStructuredData(s string) string {
	if s == "-" {
		return ""
	}
	if strings.HasPrefix(s, "- ") {
		return s[2:]
	}
	if len(s) > 0 && s[0] == '[' {
		// Walk balanced brackets (SD params may contain quoted values); MSG starts after
		// the first space that follows a closing ']' at bracket depth zero.
		depth := 0
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '[':
				depth++
			case ']':
				depth--
			case ' ':
				if depth == 0 {
					return strings.TrimSpace(s[i+1:])
				}
			}
		}
		return "" // all SD, no message
	}
	return s // no SD present
}

// parse3164: BSD format "TIMESTAMP HOSTNAME TAG: MSG" where TIMESTAMP is "Mmm dd hh:mm:ss".
func parse3164(rest string, m *Message) {
	rest = strings.TrimSpace(rest)
	// The BSD timestamp is a fixed 15 chars: "Jan  2 15:04:05".
	if len(rest) >= 15 {
		if t, err := time.Parse(time.Stamp, rest[:15]); err == nil {
			m.Timestamp = t
			rest = strings.TrimSpace(rest[15:])
		}
	}
	// Next token is the hostname.
	if sp := strings.IndexByte(rest, ' '); sp > 0 {
		m.Host = rest[:sp]
		rest = strings.TrimSpace(rest[sp+1:])
	}
	// "TAG: message" — split on the first colon for the tag/app.
	if colon := strings.IndexByte(rest, ':'); colon > 0 && colon < 40 {
		m.App = strings.TrimSpace(rest[:colon])
		m.Msg = strings.TrimSpace(rest[colon+1:])
	} else {
		m.Msg = rest
	}
}
