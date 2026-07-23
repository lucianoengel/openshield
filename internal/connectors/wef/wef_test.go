package wef

import "testing"

const logonEvent = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-07-22T10:15:30Z"/>
    <Computer>WIN-DC01.corp.local</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="IpAddress">10.0.0.5</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>`

const eventsBatch = `<Events>` + logonEvent + `
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>
    <Computer>WIN-WKS02.corp.local</Computer><Channel>Security</Channel></System>
  <EventData><Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data></EventData>
</Event></Events>`

// TestParseSingleEvent (SIEM-4): a single Windows event decodes into its documented fields + EventData.
func TestParseSingleEvent(t *testing.T) {
	recs, skipped, err := Parse([]byte(logonEvent))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if skipped != 0 || len(recs) != 1 {
		t.Fatalf("records=%d skipped=%d, want 1/0", len(recs), skipped)
	}
	r := recs[0]
	if r.EventID != "4624" || r.Provider != "Microsoft-Windows-Security-Auditing" ||
		r.Computer != "WIN-DC01.corp.local" || r.Channel != "Security" {
		t.Fatalf("wrong System fields: %+v", r)
	}
	if r.Data["TargetUserName"] != "alice" || r.Data["IpAddress"] != "10.0.0.5" || r.Data["LogonType"] != "3" {
		t.Fatalf("wrong EventData: %+v", r.Data)
	}
	if r.TimeCreated.IsZero() {
		t.Error("TimeCreated did not parse")
	}
}

// TestParseBatch (SIEM-4): an <Events> batch yields one record per <Event>.
func TestParseBatch(t *testing.T) {
	recs, _, err := Parse([]byte(eventsBatch))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	if recs[0].EventID != "4624" || recs[1].EventID != "4688" {
		t.Fatalf("wrong event ids: %q, %q", recs[0].EventID, recs[1].EventID)
	}
	if recs[1].Data["NewProcessName"] == "" {
		t.Error("second event lost its EventData")
	}
}

// TestParseRejectsMalformedAndSkipsNoEventID (SIEM-4): malformed XML is an error; an event with no
// EventID is counted-skipped, never emitted as a partial record.
//
// Mutation: if Parse returned nil,nil on a token error (treating malformed XML as empty), the malformed
// case would not error → this FAILs.
func TestParseRejectsMalformedAndSkipsNoEventID(t *testing.T) {
	if _, _, err := Parse([]byte(`<Event><System><EventID>1</EventID>`)); err == nil {
		t.Error("unterminated XML was not an error")
	}
	if _, _, err := Parse([]byte(`not xml at all <<<`)); err == nil {
		t.Error("non-XML was not an error")
	}
	// A well-formed event with no EventID → skipped, not a partial record.
	noID := `<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
	  <System><Computer>WIN-X</Computer></System></Event>
	  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
	  <System><EventID>4625</EventID><Computer>WIN-Y</Computer></System></Event></Events>`
	recs, skipped, err := Parse([]byte(noID))
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 || len(recs) != 1 || recs[0].EventID != "4625" {
		t.Fatalf("records=%v skipped=%d, want one 4625 + one skipped", recs, skipped)
	}
}
