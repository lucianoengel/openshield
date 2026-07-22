package smtp_test

import (
	"context"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/classify"
	smtpc "github.com/lucianoengel/openshield/internal/connectors/smtp"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// NIPS-3: the SMTP listener drives a REAL client (net/smtp) through a session, captures the
// message, parses it (D102), and delivers it — and the body reaches the classifier (email
// DLP runnable end to end over a real TCP session).
func TestSMTPListenerCapturesRealSession(t *testing.T) {
	var mu sync.Mutex
	var got []*smtpc.Message
	l, err := smtpc.Listen("127.0.0.1:0", func(m *smtpc.Message) {
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()

	addr := l.Addr().String()
	// A real SMTP client sends a message with a CPF in the body.
	body := "Subject: Q3\r\n\r\ncustomer CPF 111.444.777-35 attached\r\n"
	if err := smtp.SendMail(addr, nil, "alice@corp.example",
		[]string{"bob@partner.example"}, []byte(body)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no message captured within the timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	m := got[0]
	mu.Unlock()
	if m.From != "alice@corp.example" || len(m.To) != 1 || m.To[0] != "bob@partner.example" {
		t.Errorf("envelope = from %q to %v", m.From, m.To)
	}
	// The captured body reaches the classifier — a CPF is detected (email DLP).
	hits, _ := classify.New().Classify(context.Background(), strings.NewReader(string(m.Body)))
	found := false
	for _, h := range hits {
		if h.GetDetectorType() == corev1.DetectorType_DETECTOR_TYPE_CPF {
			found = true
		}
	}
	if !found {
		t.Error("a CPF in the captured email body was not detected — the SMTP body did not reach classification")
	}
}

func TestSMTPListenNilSink(t *testing.T) {
	if _, err := smtpc.Listen("127.0.0.1:0", nil, nil); err == nil {
		t.Error("Listen accepted a nil sink")
	}
}

// A malformed session (no MAIL FROM / RCPT / DATA) is dropped and COUNTED, not delivered.
func TestSMTPListenerDropsMalformedSession(t *testing.T) {
	l, err := smtpc.Listen("127.0.0.1:0", func(*smtpc.Message) {
		t.Error("a malformed session was delivered to the sink")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Read the greeting, then send an incomplete dialogue (no MAIL FROM) and quit.
	buf := make([]byte, 256)
	conn.Read(buf)
	conn.Write([]byte("EHLO x\r\nQUIT\r\n"))
	conn.Read(buf)
	conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for l.Dropped() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if l.Dropped() < 1 {
		t.Error("a malformed session was not counted as dropped")
	}
}
