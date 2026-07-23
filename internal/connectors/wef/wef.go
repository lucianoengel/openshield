// Package wef is a third-party log-ingest connector (SIEM-4): it parses Windows Event Forwarding XML —
// the standard Windows Event schema a Windows Event Collector forwards (logon 4624/4625, process
// creation 4688, privilege use, account changes) — into structured records, so OpenShield can search
// and correlate the Windows endpoint/DC estate beside CEF, CloudTrail, and its own signed telemetry.
//
// Like the CEF/CloudTrail connectors it is a PURE parser: the untrusted-bytes surface (XML from a
// collector) is handled here and tested in ordinary Go, separate from any I/O. It DECODES over the
// fixed Windows Event schema — no heuristic guessing — and interprets nothing (which EventID is "bad"
// is the policy/detector's job). Malformed XML is an error, never a partial record (D17).
package wef

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"time"
)

// MaxDelivery bounds a WEF file. A batch is many small events; a multi-hundred-MB "delivery" is a
// memory-exhaustion vector, not a log batch.
const MaxDelivery = 32 << 20

// Record is one parsed Windows event — the security-relevant subset of the schema. The full event XML
// is preserved separately (Raw) for follow-on field-level hunting.
type Record struct {
	EventID   string
	Provider  string
	Level     string    // 0..5 (0/4 informational, 2 error, 3 warning, …)
	TimeCreated time.Time
	Computer  string
	Channel   string            // e.g. "Security"
	Data      map[string]string // EventData Name -> Value
	Raw       string            // this event's XML
}

// eventXML mirrors the Windows Event schema for decoding. Fields match on LOCAL name, so the schema's
// default namespace is handled without a prefix. Unknown elements are ignored (forward-compatible).
type eventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
		Channel  string `xml:"Channel"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	// InnerXML captures the element's original inner content verbatim (System + EventData as sent), so
	// Raw is a faithful copy for field-level hunting — not a lossy re-marshal of only the decoded fields.
	InnerXML string `xml:",innerxml"`
}

// Parse decodes a WEF document — a single <Event> or an <Events> batch — into records. It scans for
// <Event> elements (matching the local name, so a namespaced or wrapped document works uniformly),
// returning the records, the number SKIPPED (an event with no EventID has no identity — counted, never
// emitted partial), and an error when the body is oversized or not well-formed XML.
func Parse(body []byte) ([]Record, int, error) {
	if len(body) == 0 {
		return nil, 0, fmt.Errorf("wef: empty body")
	}
	if len(body) > MaxDelivery {
		return nil, 0, fmt.Errorf("wef: delivery exceeds %d bytes", MaxDelivery)
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	var out []Record
	skipped := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, skipped, fmt.Errorf("wef: malformed XML: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var e eventXML
		if err := dec.DecodeElement(&e, &se); err != nil {
			return nil, skipped, fmt.Errorf("wef: decoding event: %w", err)
		}
		if e.System.EventID == "" {
			skipped++ // no event identity — counted, not emitted
			continue
		}
		rec := Record{
			EventID:  e.System.EventID,
			Provider: e.System.Provider.Name,
			Level:    e.System.Level,
			Computer: e.System.Computer,
			Channel:  e.System.Channel,
			Data:     map[string]string{},
		}
		for _, d := range e.EventData.Data {
			if d.Name != "" {
				rec.Data[d.Name] = d.Value
			}
		}
		if ts := e.System.TimeCreated.SystemTime; ts != "" {
			if t, terr := time.Parse(time.RFC3339, ts); terr == nil {
				rec.TimeCreated = t
			}
		}
		rec.Raw = "<Event>" + e.InnerXML + "</Event>" // the original inner content, faithfully
		out = append(out, rec)
	}
	return out, skipped, nil
}
