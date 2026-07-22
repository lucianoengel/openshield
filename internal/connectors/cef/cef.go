// Package cef is a third-party log-ingest connector (SIEM-4): it parses ArcSight
// Common Event Format (CEF) messages — the lingua franca of firewall/IDS/WAF/endpoint
// security logs — into structured records, so OpenShield can search and correlate the
// estate's events, not only its own signed telemetry.
//
// Like the syslog/DNS/SMTP connectors it is a PURE parser: the untrusted-bytes surface
// (a CEF line from any device) is handled here and tested in ordinary Go, separate from
// any socket. A malformed line is an error, never a partial record silently treated as
// complete (D17) — a log ingest that quietly mangles lines is a blind spot.
package cef

import (
	"fmt"
	"strings"
)

// Message is a parsed CEF event: the seven header fields and the key=value extension.
// Values are decoded faithfully; interpretation (severity scale, key semantics) is the
// consuming layer's job, not the parser's.
type Message struct {
	Version       string
	Vendor        string
	Product       string
	DeviceVersion string
	SignatureID   string
	Name          string
	Severity      string
	Extensions    map[string]string
}

// maxLine bounds a CEF line; a device that sends a multi-megabyte "line" is an
// exhaustion vector, not a log.
const maxLine = 64 << 10

// Parse decodes one CEF line. It requires the "CEF:" prefix and exactly seven
// header fields (the seventh, severity, is followed by the extension). Fewer than
// seven headers, a missing prefix, or an oversized line is an error.
func Parse(line []byte) (Message, error) {
	if len(line) == 0 {
		return Message{}, fmt.Errorf("cef: empty line")
	}
	if len(line) > maxLine {
		return Message{}, fmt.Errorf("cef: line exceeds %d bytes", maxLine)
	}
	s := string(line)
	if !strings.HasPrefix(s, "CEF:") {
		return Message{}, fmt.Errorf("cef: missing CEF: prefix")
	}
	s = s[len("CEF:"):]

	// The first six fields are pipe-delimited (honoring \| and \\); the seventh
	// (severity) runs up to the pipe that begins the extension.
	fields, rest, ok := splitHeaders(s, 7)
	if !ok {
		return Message{}, fmt.Errorf("cef: fewer than 7 header fields")
	}
	m := Message{
		Version:       unescapeHeader(fields[0]),
		Vendor:        unescapeHeader(fields[1]),
		Product:       unescapeHeader(fields[2]),
		DeviceVersion: unescapeHeader(fields[3]),
		SignatureID:   unescapeHeader(fields[4]),
		Name:          unescapeHeader(fields[5]),
		Severity:      unescapeHeader(fields[6]),
		Extensions:    parseExtension(rest),
	}
	return m, nil
}

// splitHeaders splits s into the first n fields on UNESCAPED pipes and returns them
// plus the remainder after the nth pipe. A backslash escapes the next character (so
// `\|` is a literal pipe, `\\` a literal backslash). ok is false if fewer than n
// fields were found.
func splitHeaders(s string, n int) (fields []string, rest string, ok bool) {
	fields = make([]string, 0, n)
	var cur strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			// Keep the escape sequence intact for unescapeHeader to resolve.
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i += 2
			continue
		}
		if c == '|' {
			fields = append(fields, cur.String())
			cur.Reset()
			if len(fields) == n-1 {
				// The nth field is the remainder up to the extension pipe: the extension
				// begins after the nth field. But CEF's nth field (severity) is delimited
				// by the pipe BEFORE the extension, so the nth field ends at the next pipe.
				// Find that pipe (unescaped).
				j := i + 1
				var sev strings.Builder
				for j < len(s) {
					if s[j] == '\\' && j+1 < len(s) {
						sev.WriteByte(s[j])
						sev.WriteByte(s[j+1])
						j += 2
						continue
					}
					if s[j] == '|' {
						break
					}
					sev.WriteByte(s[j])
					j++
				}
				if j >= len(s) {
					// No extension pipe: severity is the rest, no extension.
					fields = append(fields, sev.String())
					return fields, "", len(fields) == n
				}
				fields = append(fields, sev.String())
				return fields, s[j+1:], len(fields) == n
			}
			i++
			continue
		}
		cur.WriteByte(c)
		i++
	}
	// Ran out before n fields.
	return fields, "", false
}

// unescapeHeader resolves \| and \\ in a header field.
func unescapeHeader(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '|', '\\':
				b.WriteByte(s[i+1])
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseExtension decodes the `k1=v1 k2=v2 …` extension. A value may contain spaces, so
// each value runs up to the next ` key=` boundary (a space followed by a bareword key
// and `=`); values are then unescaped (\=, \\, \n, \r).
func parseExtension(s string) map[string]string {
	ext := map[string]string{}
	if s == "" {
		return ext
	}
	for len(s) > 0 {
		eq := indexUnescaped(s, '=')
		if eq < 0 {
			break // no more key=value
		}
		key := s[:eq]
		rest := s[eq+1:]
		// The value runs up to the next boundary: a space before a bareword key '='.
		end := nextKeyBoundary(rest)
		var val string
		if end < 0 {
			val = rest
			s = ""
		} else {
			val = rest[:end]
			s = rest[end+1:] // skip the boundary space
		}
		if k := strings.TrimSpace(key); k != "" {
			ext[k] = unescapeValue(val)
		}
	}
	return ext
}

// indexUnescaped returns the index of the first unescaped c, or -1.
func indexUnescaped(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == c {
			return i
		}
	}
	return -1
}

// nextKeyBoundary returns the index of the space that precedes the next `key=` in s
// (a space, then a bareword of key characters, then `=`), or -1 if none — so a value
// keeps interior spaces until a real next key.
func nextKeyBoundary(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] != ' ' {
			continue
		}
		// Look ahead: a bareword key then '='.
		j := i + 1
		for j < len(s) && isKeyChar(s[j]) {
			j++
		}
		if j > i+1 && j < len(s) && s[j] == '=' {
			return i
		}
	}
	return -1
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_'
}

// unescapeValue resolves \=, \\, \n, \r in an extension value.
func unescapeValue(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '=', '\\':
				b.WriteByte(s[i+1])
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			case 'r':
				b.WriteByte('\r')
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
