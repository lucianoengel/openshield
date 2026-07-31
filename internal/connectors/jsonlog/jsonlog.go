// Package jsonlog parses newline-delimited JSON logs into the shared external-log shape (SIEM-15).
//
// WHY THIS ONE FORMAT IS WORTH MORE THAN THE OTHERS. CEF, CloudTrail and WEF each cover one vendor's
// idea of a log. JSON lines is what everything ELSE emits: application logs, Kubernetes, GCP audit,
// Azure activity, and every shipper's default output. Adding it is not "one more format" — it is the
// difference between a SIEM that ingests three products and one that ingests an estate.
//
// It pairs with the cross-vendor vocabulary (SIEM-13): a flattened JSON document is a bag of dotted keys,
// and the field map turns whichever of them the source happened to call the user into the canonical one.
// Without that, generic ingest would just be a generic place to put logs nobody can hunt across.
//
// THE TIMESTAMP IS THE HONEST PART. A JSON log has no agreed time field, so this looks through a closed
// list of the usual names — and when none is present it says so, rather than quietly stamping the moment
// of ingest. An event whose time was invented sits in the wrong place on every timeline, and a hunt
// bounded by time misses it while reporting a clean result. The caller is told which happened.
package jsonlog

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Limits bound what one document may cost. They exist because this parses whatever an estate sends: a
// deeply nested or enormously wide document is not necessarily an attack, but treating it as unbounded
// makes the ingest path a denial of service that anyone able to write a log file can reach.
const (
	// MaxDepth is how far nesting is followed. Deeper values are recorded as their JSON text under the
	// key reached so far — kept rather than dropped, because a truncated branch an analyst can still
	// read beats a hole they cannot see.
	MaxDepth = 12
	// MaxFields caps the flattened key count. Reaching it is reported, never silent.
	MaxFields = 512
	// MaxValueBytes truncates a single value. A field this long is not a field, it is a payload.
	MaxValueBytes = 4096
)

// Record is one parsed JSON log line.
type Record struct {
	// At is the event's own timestamp. Zero when the document carried none.
	At time.Time
	// TimeSynthetic is true when At had to be supplied by the caller because the document had no
	// recognisable time field. It travels with the record so nothing downstream has to guess whether a
	// timestamp is the event's or the ingest's.
	TimeSynthetic bool
	// Host, Vendor, Product, Severity, Message are the shared external-log columns, filled from the
	// document where it names them and left empty where it does not. Empty rather than guessed: a
	// product name invented by the parser is a search facet that matches nothing an operator expects.
	Host     string
	Vendor   string
	Product  string
	Severity string
	Message  string
	// Fields is the flattened document: nested objects become dotted keys, scalars become strings.
	Fields map[string]string
	// Raw is the original line, kept verbatim so an investigator can always see what actually arrived.
	Raw string
	// Truncated reports that MaxFields was reached and the document is only partly represented. A
	// partial parse that looked complete would be the worst outcome here: a hunt over the missing keys
	// returns nothing and reads as a finding of absence.
	Truncated bool
}

// timeKeys are the field names a JSON log plausibly puts its timestamp in, in priority order.
//
// CLOSED, and short. Matching anything containing "time" would pull in `processing_time_ms` and
// `time_to_first_byte`, and a duration parsed as a date puts the event in 1970 — which is not a missing
// timestamp but a confidently wrong one, and it sorts to the top of every descending query.
var timeKeys = []string{
	"@timestamp",   // Elastic/Beats, the de facto default
	"timestamp",    //
	"eventTime",    // AWS
	"time",         // GCP, Azure
	"receivedTime", //
	"ts",           //
	"date",         //
}

// timeLayouts are the encodings those fields plausibly use.
var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05",
	time.RFC1123Z,
}

// hostKeys, vendorKeys, productKeys, severityKeys and messageKeys map the shared columns onto the names
// a JSON log plausibly uses. Same discipline as timeKeys: closed lists, so a column is filled from
// something that means it or left empty.
var (
	hostKeys     = []string{"host", "hostname", "host.name", "computer", "Computer", "source_host"}
	vendorKeys   = []string{"vendor", "observer.vendor", "cloud.provider"}
	productKeys  = []string{"product", "observer.product", "service", "service.name", "logName"}
	severityKeys = []string{"severity", "level", "log.level", "syslog.severity", "priority"}
	messageKeys  = []string{"message", "msg", "log", "event.original", "textPayload"}
)

// Parse turns one JSON object into a Record. `now` supplies the timestamp when the document has none.
//
// A document that is not an OBJECT is refused. An array or a bare scalar has no fields to hunt on, and
// storing it as a row with an empty field map would be an ingest that reports success over something
// nothing can ever match.
func Parse(line string, now time.Time) (Record, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return Record{}, fmt.Errorf("jsonlog: empty line")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
		return Record{}, fmt.Errorf("jsonlog: %w", err)
	}
	if len(doc) == 0 {
		return Record{}, fmt.Errorf("jsonlog: the document has no fields")
	}

	rec := Record{Raw: trimmed, Fields: map[string]string{}}
	flatten("", doc, rec.Fields, 0, &rec.Truncated)

	rec.At, rec.TimeSynthetic = eventTime(rec.Fields, now)
	rec.Host = firstOf(rec.Fields, hostKeys)
	rec.Vendor = firstOf(rec.Fields, vendorKeys)
	rec.Product = firstOf(rec.Fields, productKeys)
	rec.Severity = firstOf(rec.Fields, severityKeys)
	rec.Message = firstOf(rec.Fields, messageKeys)
	return rec, nil
}

// eventTime resolves the document's own timestamp, or reports that it had none.
func eventTime(fields map[string]string, now time.Time) (time.Time, bool) {
	for _, k := range timeKeys {
		v, ok := fields[k]
		if !ok || v == "" {
			continue
		}
		for _, layout := range timeLayouts {
			if t, err := time.Parse(layout, v); err == nil {
				return t.UTC(), false
			}
		}
		// Epoch seconds or milliseconds, which shippers emit as often as they emit RFC 3339.
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			switch {
			case n > 1e12: // milliseconds
				return time.UnixMilli(n).UTC(), false
			case n > 1e8: // seconds
				return time.Unix(n, 0).UTC(), false
			}
		}
	}
	return now.UTC(), true
}

// firstOf returns the first present, non-empty value among keys.
func firstOf(fields map[string]string, keys []string) string {
	for _, k := range keys {
		if v := fields[k]; v != "" {
			return v
		}
	}
	return ""
}

// flatten walks a decoded document into dotted keys.
//
// ARRAYS BECOME INDEXED KEYS (`a.0`, `a.1`) rather than a joined string. Joining loses the boundary
// between elements, so a hunt for an exact value matches a substring of two adjacent ones — a false
// positive an analyst has no way to see in the result.
func flatten(prefix string, v any, out map[string]string, depth int, truncated *bool) {
	if len(out) >= MaxFields {
		*truncated = true
		return
	}
	switch t := v.(type) {
	case map[string]any:
		if depth >= MaxDepth {
			put(out, prefix, jsonText(t), truncated)
			return
		}
		// Sorted, so a document with the same content always flattens to the same field set in the same
		// order — which is what makes the MaxFields cut reproducible rather than dependent on Go's map
		// iteration.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flatten(join(prefix, k), t[k], out, depth+1, truncated)
		}
	case []any:
		if depth >= MaxDepth {
			put(out, prefix, jsonText(t), truncated)
			return
		}
		for i, e := range t {
			flatten(join(prefix, strconv.Itoa(i)), e, out, depth+1, truncated)
		}
	case nil:
		// A null is ABSENT, not empty. The field map is what the cross-vendor projection reads, and it
		// treats an empty value as "this source does not carry it" — storing a null as "" would make a
		// source that explicitly reported no user indistinguishable from one that never has the field.
		return
	case bool:
		put(out, prefix, strconv.FormatBool(t), truncated)
	case float64:
		// json.Unmarshal gives every number as float64. Rendering 4625 as "4625" rather than "4625.000000"
		// matters: an event id an analyst pastes from a report must match the stored one exactly.
		if t == float64(int64(t)) {
			put(out, prefix, strconv.FormatInt(int64(t), 10), truncated)
			return
		}
		put(out, prefix, strconv.FormatFloat(t, 'f', -1, 64), truncated)
	case string:
		put(out, prefix, t, truncated)
	default:
		put(out, prefix, fmt.Sprint(t), truncated)
	}
}

func put(out map[string]string, key, value string, truncated *bool) {
	if key == "" {
		return
	}
	if len(out) >= MaxFields {
		*truncated = true
		return
	}
	if len(value) > MaxValueBytes {
		value = value[:MaxValueBytes]
	}
	out[key] = value
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func jsonText(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// ParseLines parses a whole newline-delimited document, returning the records and the lines that could
// not be parsed.
//
// The bad lines are RETURNED, not logged and forgotten. An estate sends malformed lines — a truncated
// shipper, a half-written file — and discarding them silently is how a SIEM comes to be trusted for
// completeness it does not have: nobody can tell "that source sent nothing" from "we could not read what
// it sent" (D31).
func ParseLines(body string, now time.Time) (records []Record, bad []error) {
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rec, err := Parse(line, now)
		if err != nil {
			bad = append(bad, err)
			continue
		}
		records = append(records, rec)
	}
	return records, bad
}
