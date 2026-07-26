// Package rfc5424 parses modern syslog (SIEM-9): the IETF format that replaced the BSD one, and the
// format most estate devices emit today when they are not emitting CEF.
//
// It earns its place over the existing BSD-syslog and CEF connectors because of STRUCTURED DATA: RFC 5424
// carries typed `[id key="value"]` elements, which map directly onto the `fields` JSONB that already backs
// cross-source hunting. A CEF extension and an RFC 5424 SD element become the same searchable key/value,
// so an analyst hunts once across both rather than learning two query shapes.
//
// Like every other connector here it is a PURE parser: the untrusted-bytes surface — a line from any
// device on the network — is handled in ordinary Go, away from any socket, and a malformed line is an
// ERROR rather than a partial record silently treated as complete (D17). A log ingest that quietly mangles
// lines is a blind spot that looks like coverage.
package rfc5424

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// maxLine bounds one message. A device sending a multi-megabyte "line" is an exhaustion vector, not a log.
const maxLine = 64 << 10

// NilValue is the RFC's explicit "absent" marker. It is decoded to an empty string rather than kept, so a
// consumer never has to know that "-" means nothing here while being a legitimate value elsewhere.
const NilValue = "-"

// Message is a parsed RFC 5424 event.
//
// Facility and Severity are DERIVED from PRI rather than stored raw, because every consumer wants them
// separated and doing the division in one place stops three call sites doing it differently.
type Message struct {
	Priority  int
	Facility  int
	Severity  int
	Version   int
	Timestamp time.Time
	Hostname  string
	AppName   string
	ProcID    string
	MsgID     string
	// StructuredData is flattened to "sdid.key" → value. Flattened rather than nested because the
	// destination is a flat JSONB map that an analyst queries with `fields->>'key'`; preserving the
	// nesting here would mean flattening it later, in a place with less context about the format.
	StructuredData map[string]string
	Message        string
}

// SeverityName maps the numeric severity to the label operators actually use. Out-of-range input yields
// "unknown" rather than an index panic — this parses bytes from the network.
func SeverityName(sev int) string {
	names := []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}
	if sev < 0 || sev >= len(names) {
		return "unknown"
	}
	return names[sev]
}

// Parse decodes one RFC 5424 line.
func Parse(line string) (Message, error) {
	var m Message
	if len(line) > maxLine {
		return m, fmt.Errorf("rfc5424: line exceeds %d bytes", maxLine)
	}
	s := strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(s, "<") {
		return m, fmt.Errorf("rfc5424: missing <PRI>")
	}
	end := strings.Index(s, ">")
	if end < 2 {
		return m, fmt.Errorf("rfc5424: malformed <PRI>")
	}
	pri, err := strconv.Atoi(s[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return m, fmt.Errorf("rfc5424: bad priority %q", s[1:end])
	}
	m.Priority, m.Facility, m.Severity = pri, pri/8, pri%8
	s = s[end+1:]

	// VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID — six space-separated fields, and
	// the RFC requires all of them. Accepting fewer would mean guessing which one is missing.
	parts := strings.SplitN(s, " ", 7)
	if len(parts) < 6 {
		return m, fmt.Errorf("rfc5424: header has %d fields, want at least 6", len(parts))
	}
	if m.Version, err = strconv.Atoi(parts[0]); err != nil || m.Version != 1 {
		return m, fmt.Errorf("rfc5424: unsupported version %q", parts[0])
	}
	if parts[1] != NilValue {
		// RFC 3339 with optional fractional seconds — exactly what time.RFC3339Nano accepts.
		if m.Timestamp, err = time.Parse(time.RFC3339Nano, parts[1]); err != nil {
			return m, fmt.Errorf("rfc5424: bad timestamp %q", parts[1])
		}
	}
	m.Hostname, m.AppName, m.ProcID, m.MsgID = nilable(parts[2]), nilable(parts[3]), nilable(parts[4]), nilable(parts[5])

	rest := ""
	if len(parts) == 7 {
		rest = parts[6]
	}
	sd, msg, err := parseStructuredData(rest)
	if err != nil {
		return m, err
	}
	m.StructuredData, m.Message = sd, msg
	return m, nil
}

func nilable(v string) string {
	if v == NilValue {
		return ""
	}
	return v
}

// parseStructuredData decodes `[id k="v" ...][id2 ...]` followed by the free-text message.
//
// Hand-written rather than regex because the escaping rules matter: inside a value, `\"`, `\\` and `\]`
// are escapes, and a regex that missed them would truncate a value at the first quoted bracket — silently,
// and only for the messages that contain one.
func parseStructuredData(s string) (map[string]string, string, error) {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return nil, "", nil
	}
	if strings.HasPrefix(s, NilValue) {
		return nil, strings.TrimLeft(strings.TrimPrefix(s, NilValue), " "), nil
	}
	if !strings.HasPrefix(s, "[") {
		return nil, s, nil // no structured data; the remainder is the message
	}
	out := map[string]string{}
	i := 0
	for i < len(s) && s[i] == '[' {
		j := i + 1
		// The SD-ID runs to the first space or the closing bracket.
		for j < len(s) && s[j] != ' ' && s[j] != ']' {
			j++
		}
		if j >= len(s) {
			return nil, "", fmt.Errorf("rfc5424: unterminated structured-data element")
		}
		id := s[i+1 : j]
		if id == "" {
			return nil, "", fmt.Errorf("rfc5424: structured-data element with no id")
		}
		i = j
		for i < len(s) && s[i] != ']' {
			for i < len(s) && s[i] == ' ' {
				i++
			}
			if i < len(s) && s[i] == ']' {
				break
			}
			k := i
			for i < len(s) && s[i] != '=' && s[i] != ']' {
				i++
			}
			if i >= len(s) || s[i] != '=' {
				return nil, "", fmt.Errorf("rfc5424: structured-data param without '='")
			}
			key := s[k:i]
			i++ // '='
			if i >= len(s) || s[i] != '"' {
				return nil, "", fmt.Errorf("rfc5424: structured-data value not quoted")
			}
			i++ // opening quote
			var val strings.Builder
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					// The RFC escapes exactly these three; anything else keeps the backslash, because
					// inventing an unescape would corrupt a value that legitimately contains one.
					switch s[i+1] {
					case '"', '\\', ']':
						val.WriteByte(s[i+1])
						i += 2
						continue
					}
				}
				if s[i] == '"' {
					break
				}
				val.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, "", fmt.Errorf("rfc5424: unterminated structured-data value")
			}
			i++ // closing quote
			out[id+"."+key] = val.String()
		}
		if i >= len(s) || s[i] != ']' {
			return nil, "", fmt.Errorf("rfc5424: unterminated structured-data element")
		}
		i++ // ']'
	}
	return out, strings.TrimLeft(s[i:], " "), nil
}
