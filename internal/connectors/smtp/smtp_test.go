package smtp_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/classify"
	smtpc "github.com/lucianoengel/openshield/internal/connectors/smtp"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

const session = "EHLO client.example\r\n" +
	"MAIL FROM:<alice@corp.example>\r\n" +
	"RCPT TO:<bob@partner.example>\r\n" +
	"RCPT TO:<carol@partner.example>\r\n" +
	"DATA\r\n" +
	"Subject: Q3 numbers\r\n" +
	"From: alice@corp.example\r\n" +
	"\r\n" +
	"Here is the customer CPF 111.444.777-35 you asked for.\r\n" +
	"..dotstuffed line stays literal\r\n" +
	".\r\n" +
	"QUIT\r\n"

func TestParseSession(t *testing.T) {
	m, err := smtpc.ParseSession([]byte(session))
	if err != nil {
		t.Fatal(err)
	}
	if m.From != "alice@corp.example" {
		t.Errorf("from = %q", m.From)
	}
	if len(m.To) != 2 || m.To[0] != "bob@partner.example" {
		t.Errorf("to = %v", m.To)
	}
	if m.Subject != "Q3 numbers" {
		t.Errorf("subject = %q", m.Subject)
	}
	// Dot-unstuffing: the client's "..dotstuffed" becomes a literal ".dotstuffed" — the
	// DOUBLE dot must be gone (asserting its absence, since ".dotstuffed" is a substring
	// of "..dotstuffed" and a mere Contains check would pass either way).
	if !strings.Contains(string(m.Body), "\n.dotstuffed line stays literal") {
		t.Errorf("dot-unstuffing failed; body = %q", m.Body)
	}
	if strings.Contains(string(m.Body), "..dotstuffed") {
		t.Errorf("double dot was not unstuffed; body = %q", m.Body)
	}
	// The "." terminator and the trailing QUIT are NOT part of the body.
	if strings.Contains(string(m.Body), "QUIT") {
		t.Error("body captured past the DATA terminator")
	}

	// The Event carries the recipient DOMAIN as metadata, not the full address.
	ev := smtpc.ToEvent("flow-1", "10.0.0.9", m)
	if ev.GetKind() != corev1.EventKind_EVENT_KIND_SMTP_MESSAGE {
		t.Errorf("kind = %v", ev.GetKind())
	}
	if ev.GetNetwork().GetSniHost() != "partner.example" {
		t.Errorf("event host = %q, want partner.example", ev.GetNetwork().GetSniHost())
	}
	// The Event must NOT carry the message body or full addresses.
	if strings.Contains(ev.GetNetwork().GetSniHost(), "bob") {
		t.Error("a full recipient address leaked into the Event")
	}
}

// The whole point: the extracted body reaches the classifier and its PII is detected
// (SMTP connector composing with the D96/D97 detectors — email DLP end to end minus sockets).
func TestSMTPBodyIsClassified(t *testing.T) {
	m, err := smtpc.ParseSession([]byte(session))
	if err != nil {
		t.Fatal(err)
	}
	hits, err := classify.New().Classify(context.Background(), strings.NewReader(string(m.Body)))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range hits {
		if h.GetDetectorType() == corev1.DetectorType_DETECTOR_TYPE_CPF {
			found = true
		}
	}
	if !found {
		t.Error("a CPF in the email body was not detected — the SMTP body did not reach classification")
	}
}

func TestParseSessionRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"no MAIL FROM":      "RCPT TO:<b@x>\r\nDATA\r\nhi\r\n.\r\n",
		"no RCPT TO":        "MAIL FROM:<a@x>\r\nDATA\r\nhi\r\n.\r\n",
		"unterminated DATA": "MAIL FROM:<a@x>\r\nRCPT TO:<b@y>\r\nDATA\r\nno dot terminator\r\n",
		"empty":             "",
	}
	for name, tc := range cases {
		if _, err := smtpc.ParseSession([]byte(tc)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}
