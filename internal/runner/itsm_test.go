package runner_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/runner"
)

// MeansClosed is the fail-safe direction, and it is the whole reason ClosedStatuses is a CLOSED vocabulary:
// "if a remote system renames a status or returns something unexpected, the fail-safe answer is 'keep
// investigating', not 'stop'."
//
// Getting this backwards would close incidents on a status nobody recognised — the investigation stops and
// the only signal is that a queue got shorter.
func TestOnlyDeclaredStatusesMeanClosed(t *testing.T) {
	c := &runner.ITSMConnector{Name: "itsm", ClosedStatuses: []string{"Resolved", "closed", "Done"}}

	for _, s := range []string{"Resolved", "resolved", "RESOLVED", "  resolved  ", "closed", "Closed", "Done"} {
		if !c.MeansClosed(s) {
			t.Errorf("MeansClosed(%q) = false; matching is case- and whitespace-insensitive, so a remote "+
				"system's capitalisation must not leave a resolved ticket open forever", s)
		}
	}
	for _, s := range []string{
		"", " ", "open", "in progress", "pending", "cancelled", "wontfix",
		"resolve",      // a prefix is NOT a match
		"resolved-ish", // nor a superstring
		"unknown-status-from-a-renamed-workflow",
	} {
		if c.MeansClosed(s) {
			t.Errorf("MeansClosed(%q) = true — an undeclared status was read as closed, which stops an "+
				"investigation on a value nobody recognised", s)
		}
	}

	// A connector with no declared statuses closes NOTHING, and a nil one does not panic.
	if (&runner.ITSMConnector{}).MeansClosed("closed") {
		t.Error("a connector declaring no closed statuses treated one as closed")
	}
	if (*runner.ITSMConnector)(nil).MeansClosed("closed") {
		t.Error("a nil connector reported a status as closed")
	}
}

// "METADATA ONLY: the pseudonymous subject (D23), the severity bucket and counts. No evidence content, no
// file contents, no classifier output beyond type and count — a ticketing system is usually the least
// access-controlled place an incident ever reaches."
//
// So the assertion is not just that the fields arrive, but that NOTHING ELSE DOES.
func TestACreatedTicketCarriesMetadataOnly(t *testing.T) {
	var raw []byte
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		auth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"ref":"INC-42","url":"https://itsm.example/INC-42"}`)
	}))
	defer srv.Close()

	c := &runner.ITSMConnector{Name: "itsm", Endpoint: srv.URL, Token: "t"}
	tk, err := c.CreateTicket(context.Background(), runner.TicketRequest{
		IncidentID: 7, Subject: "sub_abc", Severity: "high", AlertCount: 3, HostCount: 2,
		Summary: "beaconing to a known-bad host",
	})
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if tk.Ref != "INC-42" || tk.URL != "https://itsm.example/INC-42" {
		t.Fatalf("Ticket = %+v", tk)
	}
	if auth != "Bearer t" {
		t.Fatalf("Authorization = %q", auth)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("body did not parse: %v (%s)", err, raw)
	}
	allowed := map[string]bool{
		"incident_id": true, "subject": true, "severity": true,
		"alert_count": true, "host_count": true, "summary": true,
	}
	for k := range got {
		if !allowed[k] {
			t.Errorf("the ticket body carries an undeclared field %q — this payload reaches the least "+
				"access-controlled system an incident touches, so its shape is a boundary (D10/D29)", k)
		}
	}
	if got["subject"] != "sub_abc" {
		t.Errorf("subject = %v, want the pseudonym unresolved", got["subject"])
	}
}

// A ticket with no reference cannot be linked back to the incident, so it is an ERROR rather than a
// half-successful creation nobody can follow up.
func TestATicketWithNoReferenceIsAnError(t *testing.T) {
	for name, reply := range map[string]string{
		"empty ref":     `{"ref":"","url":"https://x"}`,
		"missing ref":   `{"url":"https://x"}`,
		"empty object":  `{}`,
		"not json":      `<html>gateway error</html>`,
		"json but null": `null`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, reply)
			}))
			defer srv.Close()

			c := &runner.ITSMConnector{Name: "itsm", Endpoint: srv.URL}
			if tk, err := c.CreateTicket(context.Background(), runner.TicketRequest{IncidentID: 1}); err == nil {
				t.Fatalf("a ticket was accepted with no usable reference: %+v — the incident and the "+
					"ticket could not be linked", tk)
			}
		})
	}
}

func TestANonSuccessResponseIsAnError(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusUnauthorized, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"ref":"INC-1"}`) // a body that WOULD parse, to prove the status is checked
			}))
			defer srv.Close()

			c := &runner.ITSMConnector{Name: "itsm", Endpoint: srv.URL}
			if _, err := c.CreateTicket(context.Background(), runner.TicketRequest{}); err == nil {
				t.Fatal("a non-2xx create was reported as success")
			}
			if _, err := c.TicketStatus(context.Background(), "INC-1"); err == nil {
				t.Fatal("a non-2xx status poll was reported as success")
			}
		})
	}
}

func TestTicketStatusPollsTheTicketsOwnURL(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = io.WriteString(w, `{"status":"Resolved"}`)
	}))
	defer srv.Close()

	// A trailing slash on the configured endpoint must not produce a doubled one in the polled URL.
	for _, endpoint := range []string{srv.URL + "/tickets", srv.URL + "/tickets/"} {
		c := &runner.ITSMConnector{Name: "itsm", Endpoint: endpoint}
		got, err := c.TicketStatus(context.Background(), "INC-42")
		if err != nil {
			t.Fatalf("TicketStatus via %q: %v", endpoint, err)
		}
		if got != "Resolved" {
			t.Fatalf("status = %q, want Resolved", got)
		}
		if path != "/tickets/INC-42" {
			t.Fatalf("polled %q via endpoint %q, want /tickets/INC-42", path, endpoint)
		}
		if strings.Contains(path, "//") {
			t.Fatalf("polled a doubled-slash path %q", path)
		}
	}
}
