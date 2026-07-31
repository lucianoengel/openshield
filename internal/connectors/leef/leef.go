// Package leef parses IBM QRadar's Log Event Extended Format (SIEM-16).
//
// LEEF is CEF's sibling and the second format security appliances actually speak: where an ArcSight
// estate emits CEF, a QRadar one emits LEEF, and an estate that has bought from both emits both. A
// deployment that reads one and not the other is not covering "most of the estate" — it is covering
// whichever half of it was bought first.
//
// THE DELIMITER IS THE WHOLE DIFFICULTY, and it is the reason this is a parser rather than a rename of
// the CEF one. CEF separates its attributes with spaces; LEEF 1.0 separates them with TABS; and LEEF 2.0
// adds a SIXTH header field naming a custom delimiter, which may be given literally or as a hex escape
// (`x09`, `0x09`). A parser that assumes tab does not fail on a LEEF 2.0 record using `^` — it succeeds,
// producing ONE enormous key nobody will ever search for. Every event from that appliance is then stored,
// counted as ingested, and invisible to every hunt.
//
// Like the CEF connector this is a PURE parser: the untrusted-bytes surface is handled here and tested in
// ordinary Go, separate from any socket. A malformed line is an error, never a partial record silently
// treated as complete.
package leef

import (
	"fmt"
	"strconv"
	"strings"
)

// Message is a parsed LEEF event: the header fields and the delimited attributes.
type Message struct {
	Version       string // "1.0" or "2.0"
	Vendor        string
	Product       string
	DeviceVersion string
	EventID       string
	// Delimiter is the attribute separator actually used, resolved from the LEEF 2.0 header field or
	// defaulted to tab. Kept on the record because "which delimiter did we read this with" is the first
	// question when an appliance's events come back as one giant field.
	Delimiter  string
	Attributes map[string]string
}

// maxLine bounds a LEEF line; an appliance sending a multi-megabyte "line" is an exhaustion vector, not
// a log. Same ceiling as the CEF connector, for the same reason.
const maxLine = 64 << 10

// defaultDelimiter is LEEF's attribute separator when the header does not name one.
const defaultDelimiter = "\t"

// Parse decodes one LEEF line.
//
// LEEF 1.0: LEEF:1.0|Vendor|Product|Version|EventID|key=value<TAB>key=value
// LEEF 2.0: LEEF:2.0|Vendor|Product|Version|EventID|<delimiter>|key=value<delim>key=value
//
// The two are distinguished by the VERSION, not by counting pipes, because an attribute value may
// legitimately contain a pipe and counting would mis-split exactly the records that carry a URL.
func Parse(line []byte) (Message, error) {
	if len(line) == 0 {
		return Message{}, fmt.Errorf("leef: empty line")
	}
	if len(line) > maxLine {
		return Message{}, fmt.Errorf("leef: line exceeds %d bytes", maxLine)
	}
	s := string(line)
	if !strings.HasPrefix(s, "LEEF:") {
		return Message{}, fmt.Errorf("leef: missing LEEF: prefix")
	}
	s = s[len("LEEF:"):]

	// Five header fields always, then either the attributes (1.0) or the delimiter field (2.0).
	fields, rest, ok := splitHeaders(s, 5)
	if !ok {
		return Message{}, fmt.Errorf("leef: fewer than 5 header fields")
	}
	m := Message{
		Version:       unescape(fields[0]),
		Vendor:        unescape(fields[1]),
		Product:       unescape(fields[2]),
		DeviceVersion: unescape(fields[3]),
		EventID:       unescape(fields[4]),
		Delimiter:     defaultDelimiter,
	}
	if m.Version == "" {
		return Message{}, fmt.Errorf("leef: no version in the header")
	}

	if strings.HasPrefix(m.Version, "2") {
		// The sixth field names the delimiter. It may be EMPTY, which means "the default" — an empty
		// field is not an error and must not be read as a zero-length separator, which would split
		// between every character.
		raw, attrs, found := strings.Cut(rest, "|")
		if !found {
			return Message{}, fmt.Errorf("leef: 2.0 header has no delimiter field")
		}
		d, derr := resolveDelimiter(raw)
		if derr != nil {
			return Message{}, derr
		}
		m.Delimiter = d
		rest = attrs
	}
	m.Attributes = parseAttributes(rest, m.Delimiter)
	return m, nil
}

// resolveDelimiter turns the LEEF 2.0 delimiter field into the separator to split on.
//
// The field may be a literal character, or a hex escape in any of the forms appliances actually emit:
// `x09`, `X09`, `0x09`, `\x09`. An unrecognised multi-character value is an ERROR rather than a
// fallback to tab: falling back would parse the record with the wrong separator, producing one enormous
// key that is stored, counted as ingested, and invisible to every hunt — which is worse than refusing
// the line, because a refused line is counted as dropped and an operator can see it.
func resolveDelimiter(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return defaultDelimiter, nil
	case len([]rune(raw)) == 1:
		return raw, nil
	}
	hex := raw
	for _, p := range []string{"\\x", "0x", "0X", "x", "X"} {
		if strings.HasPrefix(hex, p) {
			hex = hex[len(p):]
			break
		}
	}
	if hex != raw || len(hex) <= 2 {
		if n, err := strconv.ParseUint(hex, 16, 8); err == nil {
			return string(rune(n)), nil
		}
	}
	return "", fmt.Errorf("leef: unrecognised delimiter field %q — parsing with the wrong separator "+
		"yields one enormous key that is stored, counted as ingested, and invisible to every hunt", raw)
}

// parseAttributes splits the attribute section on the resolved delimiter and each pair on the first '='.
//
// A fragment with no '=' is SKIPPED rather than stored under an empty key: an empty key is not
// searchable, and one such fragment would otherwise collide with and overwrite the next.
func parseAttributes(s, delim string) map[string]string {
	out := map[string]string{}
	if s == "" {
		return out
	}
	for _, part := range strings.Split(s, delim) {
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// splitHeaders splits s into the first n pipe-delimited fields, honouring `\|` and `\\`, and returns the
// remainder. Escape-aware because a vendor or product name containing a pipe is legal and splitting
// naively would shift every later field — silently, and only for that vendor.
func splitHeaders(s string, n int) (fields []string, rest string, ok bool) {
	fields = make([]string, 0, n)
	var cur strings.Builder
	esc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if esc {
			cur.WriteByte(c)
			esc = false
			continue
		}
		switch c {
		case '\\':
			esc = true
		case '|':
			fields = append(fields, cur.String())
			cur.Reset()
			if len(fields) == n {
				return fields, s[i+1:], true
			}
		default:
			cur.WriteByte(c)
		}
	}
	return nil, "", false
}

// unescape decodes the header escapes LEEF shares with CEF: `\|` and `\\`.
func unescape(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// leefMarker is where a LEEF payload begins inside a syslog line.
const leefMarker = "LEEF:"

// FromSyslog extracts and parses a LEEF payload carried inside a syslog message.
//
// Appliances send LEEF the way they send CEF — wrapped in a syslog line whose header this parser has no
// business reading. Finding the marker rather than requiring the payload to start the message is what
// lets one listener accept both formats from an estate that emits both, which most estates do.
func FromSyslog(syslogMsg string) (Message, bool) {
	i := strings.Index(syslogMsg, leefMarker)
	if i < 0 {
		return Message{}, false
	}
	m, err := Parse([]byte(syslogMsg[i:]))
	if err != nil {
		return Message{}, false
	}
	return m, true
}

// MarkerLine returns the LEEF payload from its marker, so the stored raw line is the event and not the
// syslog framing around it.
func MarkerLine(syslogMsg string) string {
	if i := strings.Index(syslogMsg, leefMarker); i >= 0 {
		return syslogMsg[i:]
	}
	return syslogMsg
}
