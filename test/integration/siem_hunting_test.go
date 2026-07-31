//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// HUNTING ACROSS THREE VENDORS' LOGS, IN A RUNNING DEPLOYMENT (D425/D426).
//
// The package tests prove the map and the saved-search validator. What they cannot prove is the thing the
// analyst actually depends on: that logs which arrived through THREE DIFFERENT INGEST PATHS — a syslog
// listener, a CloudTrail directory poller, a WEF directory poller — can be reached by one query against
// the shipped API, over mutual TLS, at the tier an analyst holds.
//
// That combination is where the failure would hide. Each ingester normalises differently, the vocabulary
// is applied on read, and the endpoint is role-gated: any one of those being wrong produces FEWER ROWS,
// which reads as "nothing happened" rather than as an error.

// oneUser is the same principal in three vocabularies. The value is identical on purpose — that is the
// whole claim: one hunt, one name, three sources.
const oneUser = "alice"

// seedThreeVendors ingests a log for the same user through each of the three real paths and returns the
// server. The CEF one goes over a real UDP socket; the other two land as files a poller picks up.
func seedThreeVendors(t *testing.T, p *pki) (*Stack, *Process, string) {
	t.Helper()
	ctDir, wefDir := t.TempDir(), t.TempDir()
	cefAddr := "127.0.0.1:" + freePort(t)

	// CloudTrail: the actor is `userIdentity.arn`.
	trail := fmt.Sprintf(`{"Records":[{"eventTime":"2026-07-27T10:00:00Z","eventSource":"s3.amazonaws.com",`+
		`"eventName":"GetObject","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.5",`+
		`"userIdentity":{"arn":%q}}]}`, oneUser)
	if err := os.WriteFile(filepath.Join(ctDir, "trail.json"), []byte(trail), 0o600); err != nil {
		t.Fatal(err)
	}
	// Windows: the actor is `SubjectUserName`.
	wef := fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">`+
		`<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>`+
		`<TimeCreated SystemTime="2026-07-27T10:05:00Z"/><Computer>WS-01</Computer></System>`+
		`<EventData><Data Name="SubjectUserName">%s</Data>`+
		`<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data></EventData></Event>`, oneUser)
	if err := os.WriteFile(filepath.Join(wefDir, "sec.xml"), []byte(wef), 0o600); err != nil {
		t.Fatal(err)
	}

	stack, srv, base := mtlsServer(t, p, map[string]string{
		"OPENSHIELD_CLOUDTRAIL_DIR":       ctDir,
		"OPENSHIELD_WEF_DIR":              wefDir,
		"OPENSHIELD_CEF_SYSLOG_LISTEN":    cefAddr,
		"OPENSHIELD_CORRELATE_INTERVAL":   "0s",
		"OPENSHIELD_CORRELATE_MIN_ALERTS": "3",
	})
	srv.WaitForOutput("CEF-over-syslog listener on", 90*time.Second)
	srv.WaitForOutput("CloudTrail ingest watching", 60*time.Second)
	srv.WaitForOutput("WEF ingest watching", 60*time.Second)

	// CEF: the actor is `suser`. Sent over the wire, repeatedly, because UDP may be dropped before the
	// listener is fully ready and a single datagram would make this flaky for a reason unrelated to the
	// feature.
	pool := openPool(t, stack.DSN)
	cef := fmt.Sprintf(`<134>1 2026-07-27T10:10:00Z fw01 CEF - - - `+
		`CEF:0|Vendor|Firewall|1.0|100|Blocked connection|5|suser=%s src=203.0.113.5 dst=10.0.0.5`, oneUser)
	sendUntil(t, cefAddr, cef, "the CEF event to be stored", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM external_logs WHERE product='Firewall'`).Scan(&n)
		return n > 0
	})
	for _, want := range []string{"cloudtrail", "windows"} {
		w := want
		Eventually(t, 120*time.Second, "the "+w+" record to be ingested", func() bool {
			var n int
			_ = pool.QueryRow(Ctx(t),
				`SELECT count(*) FROM external_logs WHERE product=$1`, w).Scan(&n)
			return n > 0
		})
	}
	return stack, srv, base
}

// TestOneCanonicalHuntReachesEveryIngestPath (D425).
//
// Mutation (drop the alias expansion in SearchExternalLogs, or stop projecting Normalized onto the
// result): the canonical hunt returns 0 rows, because no source stores a field called "user" → FAIL.
func TestOneCanonicalHuntReachesEveryIngestPath(t *testing.T) {
	p := newPKI(t)
	_, _, base := seedThreeVendors(t, p)
	analyst := p.operator(t, "analyst", "carol")

	// FIRST, the vocabulary is discoverable. A normalisation nobody can enumerate is one an analyst has
	// to learn from the source code.
	code, body := do(t, analyst, http.MethodGet, base+"/logs/fields", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /logs/fields = %d: %s", code, body)
	}
	var vocab struct {
		Canonical []string            `json:"canonical"`
		Aliases   map[string][]string `json:"aliases"`
	}
	if err := json.Unmarshal([]byte(body), &vocab); err != nil {
		t.Fatalf("decoding the vocabulary: %v (%s)", err, body)
	}
	if len(vocab.Canonical) == 0 || len(vocab.Aliases["user"]) == 0 {
		t.Fatalf("the published vocabulary is empty or does not cover `user`: %s", body)
	}

	// THE HUNT. One query, one name, three ingest paths.
	code, body = do(t, analyst, http.MethodGet,
		base+"/logs?field=user:"+url.QueryEscape(oneUser)+"&limit=50", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /logs = %d: %s", code, body)
	}
	var logs []struct {
		Vendor     string            `json:"Vendor"`
		Product    string            `json:"Product"`
		Fields     map[string]string `json:"Fields"`
		Normalized map[string]string `json:"Normalized"`
	}
	if err := json.Unmarshal([]byte(body), &logs); err != nil {
		t.Fatalf("decoding /logs: %v (%s)", err, body)
	}
	products := map[string]bool{}
	for _, l := range logs {
		products[l.Product] = true
		if l.Normalized["user"] != oneUser {
			t.Errorf("%s/%s came back without a canonical user (%q) — the analyst reading the result "+
				"still has to know this vendor's own field name", l.Vendor, l.Product, l.Normalized["user"])
		}
		if len(l.Fields) == 0 {
			t.Errorf("%s/%s lost its raw fields — normalisation is additive, never a replacement",
				l.Vendor, l.Product)
		}
	}
	for _, want := range []string{"Firewall", "cloudtrail", "windows"} {
		if !products[want] {
			t.Fatalf("one canonical hunt for user=%s returned %d log(s) covering %v, missing %q. A hunt "+
				"that misses a source returns FEWER ROWS and reads as a narrower blast radius, so the "+
				"gap looks like good news", oneUser, len(logs), keysOf(products), want)
		}
	}

	// A VENDOR'S OWN FIELD NAME IS NOT WIDENED. Silently broadening a precise query is the same wrong
	// answer as missing a source, with the sign flipped.
	code, body = do(t, analyst, http.MethodGet,
		base+"/logs?field=suser:"+url.QueryEscape(oneUser)+"&limit=50", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /logs (vendor key) = %d: %s", code, body)
	}
	var narrow []struct {
		Product string `json:"Product"`
	}
	if err := json.Unmarshal([]byte(body), &narrow); err != nil {
		t.Fatal(err)
	}
	for _, l := range narrow {
		if l.Product != "Firewall" {
			t.Fatalf("hunting the CEF-specific key `suser` also matched %q — an analyst's precise query "+
				"must keep meaning exactly what it meant", l.Product)
		}
	}
}

// TestASavedHuntIsRunnableByTheWholeTeam (D426).
//
// The whole point is that a hunt survives the person who wrote it, so it is SAVED by one operator and RUN
// by a different one, each with their own certificate, against a server that never sees a request field
// naming either of them.
//
// Mutation (drop the /searches/save route, or gate the run above the analyst tier): the save 404s or the
// analyst's run is refused → FAIL.
func TestASavedHuntIsRunnableByTheWholeTeam(t *testing.T) {
	p := newPKI(t)
	_, _, base := seedThreeVendors(t, p)
	responder := p.operator(t, "responder", "bob")
	analyst := p.operator(t, "analyst", "carol")

	saveURL := base + "/searches/save?name=alice-across-the-estate&surface=logs&query=" +
		url.QueryEscape("field=user:"+oneUser+"&limit=50") +
		"&description=" + url.QueryEscape("everything this principal did, in any vendor's words")
	code, body := do(t, responder, http.MethodPost, saveURL, nil)
	if code != http.StatusOK {
		t.Fatalf("saving the hunt = %d: %s", code, body)
	}

	// An ANALYST — who cannot author one — runs it and gets the same three vendors.
	code, body = do(t, analyst, http.MethodGet, base+"/searches/run?name=alice-across-the-estate", nil)
	if code != http.StatusOK {
		t.Fatalf("running the saved hunt = %d: %s", code, body)
	}
	var run struct {
		Surface string `json:"surface"`
		Results []struct {
			Product    string            `json:"Product"`
			Normalized map[string]string `json:"Normalized"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(body), &run); err != nil {
		t.Fatalf("decoding the run: %v (%s)", err, body)
	}
	if run.Surface != "logs" {
		t.Errorf("the run reports surface %q, want logs", run.Surface)
	}
	products := map[string]bool{}
	for _, r := range run.Results {
		products[r.Product] = true
	}
	for _, want := range []string{"Firewall", "cloudtrail", "windows"} {
		if !products[want] {
			t.Fatalf("the saved hunt returned %v, missing %q — a hunt that returns less than the query "+
				"its author tested is worse than none, because both return rows and nobody finds out "+
				"which they are looking at", keysOf(products), want)
		}
	}

	// AUTHORING IS A HIGHER TIER THAN RUNNING. A saved search is a tool the whole team will run and
	// trust, so an analyst may use one and may not write one.
	code, _ = do(t, analyst, http.MethodPost,
		base+"/searches/save?name=analyst-written&surface=logs&query="+url.QueryEscape("limit=1"), nil)
	if code == http.StatusOK {
		t.Fatal("an ANALYST authored a saved search — the read and write surfaces are separate paths " +
			"precisely so that the role gate can differ between them")
	}

	// AND AN UNRUNNABLE HUNT IS REFUSED WHEN IT IS SAVED, not during the incident it was saved for.
	code, body = do(t, responder, http.MethodPost,
		base+"/searches/save?name=broken&surface=logs&query="+url.QueryEscape("since=yesterday"), nil)
	if code != http.StatusBadRequest {
		t.Fatalf("saving a hunt whose query the surface's parser rejects = %d, want 400: %s", code, body)
	}

	// The saved one is listed, with its author recorded.
	code, body = do(t, analyst, http.MethodGet, base+"/searches", nil)
	if code != http.StatusOK {
		t.Fatalf("listing saved searches = %d: %s", code, body)
	}
	if !strings.Contains(body, "alice-across-the-estate") {
		t.Fatalf("the saved hunt is not listed: %s", body)
	}
	if !strings.Contains(body, "bob") {
		t.Errorf("the listing does not record who wrote the hunt — a reviewer asking about its intent "+
			"has nobody to ask: %s", body)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestJSONLinesLogsAreIngestedAndHuntableWithEveryoneElse (D435 / SIEM-15).
//
// CEF, CloudTrail and WEF each cover one vendor. JSON lines is what everything ELSE emits, so the claim
// worth proving is not that it parses — the package tests do that — but that a file dropped in a
// directory becomes a row the SAME canonical query reaches, alongside the three formats that were
// already there. A format that ingests into its own corner is a place to put logs, not a SIEM.
func TestJSONLinesLogsAreIngestedAndHuntableWithEveryoneElse(t *testing.T) {
	p := newPKI(t)
	jsonDir := t.TempDir()

	// The same principal again, in a fourth vocabulary: nested, the way an application log names things.
	line := fmt.Sprintf(`{"@timestamp":"2026-07-27T10:20:00Z","service":{"name":"checkout"},`+
		`"user":{"name":%q},"src":{"ip":"203.0.113.5"},"message":"payment refused"}`, oneUser)
	if err := os.WriteFile(filepath.Join(jsonDir, "app.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stack, srv, base := mtlsServer(t, p, map[string]string{
		"OPENSHIELD_JSONLOG_DIR":    jsonDir,
		"OPENSHIELD_JSONLOG_VENDOR": "acme",
	})
	srv.WaitForOutput("JSON-lines ingest watching", 90*time.Second)
	pool := openPool(t, stack.DSN)
	Eventually(t, 120*time.Second, "the JSON record to be ingested", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM external_logs WHERE vendor='acme'`).Scan(&n)
		return n > 0
	})

	analyst := p.operator(t, "analyst", "carol")
	code, body := do(t, analyst, http.MethodGet,
		base+"/logs?field=user:"+url.QueryEscape(oneUser)+"&limit=50", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /logs = %d: %s", code, body)
	}
	var logs []struct {
		Vendor     string            `json:"Vendor"`
		Product    string            `json:"Product"`
		Fields     map[string]string `json:"Fields"`
		Normalized map[string]string `json:"Normalized"`
	}
	if err := json.Unmarshal([]byte(body), &logs); err != nil {
		t.Fatalf("decoding /logs: %v (%s)", err, body)
	}
	var found bool
	for _, l := range logs {
		if l.Vendor != "acme" {
			continue
		}
		found = true
		if l.Product != "checkout" {
			t.Errorf("product = %q, want the service the document named", l.Product)
		}
		// The NESTED key is flat and huntable, and the canonical projection reached it.
		if l.Fields["src.ip"] != "203.0.113.5" {
			t.Errorf("the nested source IP did not flatten (%q) — a document searchable only by its "+
				"top-level keys is stored, not ingested", l.Fields["src.ip"])
		}
		if l.Normalized["user"] != oneUser {
			t.Errorf("the canonical projection did not reach the JSON record (%q) — a format that "+
				"ingests into its own corner is a place to put logs, not a SIEM",
				l.Normalized["user"])
		}
	}
	if !found {
		t.Fatalf("the canonical hunt for user=%s did not reach the JSON-lines record at all", oneUser)
	}

	// The file is marked processed, so a restart does not re-ingest it.
	Eventually(t, 60*time.Second, "the ingested file to be marked", func() bool {
		_, err := os.Stat(filepath.Join(jsonDir, "app.jsonl.ingested"))
		return err == nil
	})
}

// TestLEEFArrivesOnTheSameListenerAsCEF (SIEM-16).
//
// The package tests prove the parser. What only a running deployment proves is that ONE listener accepts
// both formats — because that is the actual operational claim. An estate that has bought from both
// ArcSight and QRadar emits both, and making an operator run a second port per format is how a log
// source ends up not onboarded at all.
//
// The LEEF 2.0 record uses a CUSTOM DELIMITER on purpose. A listener that assumed tab would not fail on
// it: it would store one enormous key, count the event as ingested, and leave it invisible to every
// hunt. The assertion is therefore on the FIELDS, never on the row existing.
func TestLEEFArrivesOnTheSameListenerAsCEF(t *testing.T) {
	p := newPKI(t)
	cefAddr := "127.0.0.1:" + freePort(t)
	stack, srv, base := mtlsServer(t, p, map[string]string{
		"OPENSHIELD_CEF_SYSLOG_LISTEN":  cefAddr,
		"OPENSHIELD_CORRELATE_INTERVAL": "0s",
	})
	srv.WaitForOutput("CEF-over-syslog listener on", 90*time.Second)
	pool := openPool(t, stack.DSN)

	// A LEEF 2.0 record with a caret delimiter, wrapped in syslog the way an appliance sends it.
	leefLine := "<134>1 2026-07-27T10:30:00Z qradar-fw LEEF - - - " +
		"LEEF:2.0|Acme|Firewall|2.1|4711|^|" +
		"src=203.0.113.5^dst=10.0.0.5^usrName=" + oneUser + "^sev=7^msg=Blocked connection"
	sendUntil(t, cefAddr, leefLine, "the LEEF event to be stored", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM external_logs WHERE vendor='Acme'`).Scan(&n)
		return n > 0
	})

	// A CEF record on the SAME port, so this proves coexistence rather than a listener that swapped one
	// format for the other.
	cefLine := "<134>1 2026-07-27T10:31:00Z arcsight-fw CEF - - - " +
		"CEF:0|Vendor|Firewall|1.0|100|Blocked connection|5|suser=" + oneUser + " src=203.0.113.5"
	sendUntil(t, cefAddr, cefLine, "the CEF event to be stored on the same listener", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM external_logs WHERE product='Firewall' AND vendor='Vendor'`).Scan(&n)
		return n > 0
	})

	// THE FIELDS SURVIVED THE CUSTOM DELIMITER, and the canonical hunt reaches both formats at once.
	analyst := p.operator(t, "analyst", "carol")
	code, body := do(t, analyst, http.MethodGet,
		base+"/logs?field=user:"+url.QueryEscape(oneUser)+"&limit=50", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /logs = %d: %s", code, body)
	}
	var logs []struct {
		Vendor     string            `json:"Vendor"`
		Fields     map[string]string `json:"Fields"`
		Normalized map[string]string `json:"Normalized"`
	}
	if err := json.Unmarshal([]byte(body), &logs); err != nil {
		t.Fatalf("decoding /logs: %v (%s)", err, body)
	}
	vendors := map[string]bool{}
	for _, l := range logs {
		vendors[l.Vendor] = true
		if l.Vendor == "Acme" {
			if l.Fields["dst"] != "10.0.0.5" || l.Fields["sev"] != "7" {
				t.Fatalf("the LEEF attributes did not survive the caret delimiter (%v) — a listener "+
					"assuming tab would store one enormous key, count the event as ingested, and leave "+
					"it invisible to every hunt", l.Fields)
			}
		}
	}
	for _, want := range []string{"Acme", "Vendor"} {
		if !vendors[want] {
			t.Fatalf("one canonical hunt reached %v, missing %q — an estate emits both formats, and a "+
				"deployment that reads one covers whichever half was bought first",
				keysOf(vendors), want)
		}
	}
}

// TestSysmonEventsArriveNamedAndHuntable (SIEM-17).
//
// Sysmon events already arrived before this — the WEF poller parsed them and stored their EventData.
// What only a running deployment shows is whether they arrive USABLE: named by their action rather than
// by a number, and reachable through the same canonical vocabulary as everything else.
//
// The assertion is deliberately on a CROSS-SOURCE hunt. `Image` answering the same question as a Linux
// exec path is the entire point of the naming layer; a Sysmon record that is only findable by Sysmon's
// own field names has been ingested into its own corner.
func TestSysmonEventsArriveNamedAndHuntable(t *testing.T) {
	p := newPKI(t)
	wefDir := t.TempDir()

	// A Sysmon 1 (process create) and a Sysmon 22 (DNS query) — the two an investigation pivots on.
	sysmonXML := `<Events>` +
		`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` +
		`<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>` +
		`<TimeCreated SystemTime="2026-07-27T11:00:00Z"/><Computer>WS-14</Computer></System>` +
		`<EventData><Data Name="Image">C:\Windows\System32\cmd.exe</Data>` +
		`<Data Name="ParentImage">C:\Windows\explorer.exe</Data>` +
		`<Data Name="User">` + oneUser + `</Data></EventData></Event>` +
		`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` +
		`<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>22</EventID>` +
		`<TimeCreated SystemTime="2026-07-27T11:01:00Z"/><Computer>WS-14</Computer></System>` +
		`<EventData><Data Name="QueryName">c2.evil.example</Data>` +
		`<Data Name="User">` + oneUser + `</Data></EventData></Event>` +
		`</Events>`
	if err := os.WriteFile(filepath.Join(wefDir, "sysmon.xml"), []byte(sysmonXML), 0o600); err != nil {
		t.Fatal(err)
	}

	stack, srv, base := mtlsServer(t, p, map[string]string{
		"OPENSHIELD_WEF_DIR":            wefDir,
		"OPENSHIELD_CORRELATE_INTERVAL": "0s",
	})
	srv.WaitForOutput("WEF ingest watching", 90*time.Second)
	pool := openPool(t, stack.DSN)
	Eventually(t, 120*time.Second, "the Sysmon events to be ingested", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM external_logs WHERE product='sysmon'`).Scan(&n)
		return n >= 2
	})

	// NAMED BY ACTION, not by number.
	var names []string
	rows, err := pool.Query(Ctx(t), `SELECT name FROM external_logs WHERE product='sysmon' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	rows.Close()
	want := map[string]bool{"process_create": true, "dns_query": true}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) > 0 {
		t.Fatalf("the Sysmon events are stored as %v — an event stored as its NUMBER is huntable only "+
			"by someone who has memorised Microsoft's table, which in practice means by nobody, and the "+
			"richest Windows source in the estate sits in the store being counted", names)
	}

	// AND REACHABLE BY THE SHARED VOCABULARY. `Image` must answer the same question as a Linux exec
	// path, or Sysmon has been ingested into its own corner.
	analyst := p.operator(t, "analyst", "carol")
	for _, hunt := range []struct{ field, value, why string }{
		{"user", oneUser, "the Sysmon User field must answer the same hunt as every other source's"},
		{"process", `C:\Windows\System32\cmd.exe`, "Image is the process the event is ABOUT, never ParentImage"},
		{"domain", "c2.evil.example", "a DNS query from an endpoint is the pivot an investigation starts from"},
	} {
		h := hunt
		code, body := do(t, analyst, http.MethodGet,
			base+"/logs?field="+h.field+":"+url.QueryEscape(h.value)+"&limit=50", nil)
		if code != http.StatusOK {
			t.Fatalf("GET /logs (%s) = %d: %s", h.field, code, body)
		}
		var logs []struct {
			Product    string            `json:"Product"`
			Normalized map[string]string `json:"Normalized"`
		}
		if err := json.Unmarshal([]byte(body), &logs); err != nil {
			t.Fatal(err)
		}
		var hit bool
		for _, l := range logs {
			if l.Product != "sysmon" {
				continue
			}
			hit = true
			// THE PROJECTED VALUE, not merely the row. The query ORs every alias, so a record is found
			// whichever alias carries the value — ordering inside the map is invisible to the search
			// and visible only HERE, in what the analyst reads. `Image` before `ParentImage` is what
			// stops every process_create on the host being attributed to explorer.exe.
			if got := l.Normalized[h.field]; got != h.value {
				t.Fatalf("the Sysmon record projects %s=%q, want %q — %s",
					h.field, got, h.value, h.why)
			}
		}
		if !hit {
			t.Fatalf("the canonical hunt %s=%q did not reach the Sysmon record — %s",
				h.field, h.value, h.why)
		}
	}
}
