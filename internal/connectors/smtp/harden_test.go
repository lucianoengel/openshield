package smtp_test

import (
	"context"
	"net"
	"testing"
	"time"

	smtpc "github.com/lucianoengel/openshield/internal/connectors/smtp"
)

// NIPS-3-SMTP: a stream with NO newline must not make the listener buffer unbounded (OOM) — the
// session is bounded and dropped, and the listener stays responsive. We can't assert "did not OOM"
// directly, so we assert the connection is handled to completion (dropped+counted) within a short
// bound rather than hanging or growing forever.
func TestSMTPNoNewlineIsBounded(t *testing.T) {
	l, err := smtpc.Listen("127.0.0.1:0", func(*smtpc.Message) {
		t.Error("a no-newline flood was delivered as a valid message")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.IdleTimeout = 500 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 256)
	conn.Read(buf) // greeting
	// Send a chunk with NO newline, then stop. The LimitReader + idle deadline must end the session.
	conn.Write([]byte("MAIL FROM:<a@b> and then a lot of bytes with no newline "))
	chunk := make([]byte, 64<<10)
	for i := range chunk {
		chunk[i] = 'x'
	}
	// Write a bit more (still no newline); a bounded reader will stop reading and the deadline fires.
	_, _ = conn.Write(chunk)

	deadline := time.Now().Add(3 * time.Second)
	for l.Dropped() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if l.Dropped() < 1 {
		t.Error("a no-newline session was not bounded/dropped within the timeout (possible unbounded read)")
	}
}

// An idle connection that sends nothing after the greeting is timed out and dropped, not held.
func TestSMTPIdleConnectionTimesOut(t *testing.T) {
	l, _ := smtpc.Listen("127.0.0.1:0", func(*smtpc.Message) {}, nil)
	l.IdleTimeout = 300 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 256)
	conn.Read(buf) // greeting, then send NOTHING

	// The server should close its side within ~IdleTimeout; a read then returns EOF/reset promptly.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	for {
		if _, err := conn.Read(buf); err != nil {
			break // server closed (or our deadline) — either way it did not hang open
		}
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Error("an idle connection was not timed out promptly (slowloris exposure)")
	}
}

// The concurrency cap refuses connections beyond MaxConns rather than spawning unbounded handlers.
func TestSMTPConcurrencyCapped(t *testing.T) {
	l, _ := smtpc.Listen("127.0.0.1:0", func(*smtpc.Message) {}, nil)
	l.MaxConns = 2
	l.IdleTimeout = 3 * time.Second // hold the handled conns open so the cap is exercised
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()
	addr := l.Addr().String()

	// Open more connections than the cap and keep them idle (they hold the semaphore while their
	// handler blocks on read). Beyond the cap, connections are refused + counted.
	var conns []net.Conn
	for i := 0; i < 6; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			continue
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for l.Refused() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if l.Refused() < 1 {
		t.Errorf("opened 6 connections with MaxConns=2 but Refused()=%d — the cap is not enforced", l.Refused())
	}
}
