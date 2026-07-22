package smtp_test

import (
	"context"
	"net"
	"testing"
	"time"

	smtpc "github.com/lucianoengel/openshield/internal/connectors/smtp"
)

// NIPS-3-SMTP: a stream with NO newline must not make the listener buffer unbounded (OOM). The bound
// is the per-session SIZE CEILING (io.LimitReader) — the `total > maxBody` check only advances on
// completed lines, so a newline-less flood is bounded solely by the LimitReader. This test proves
// THAT guard, not the idle deadline: it sets a small MaxBody and a LARGE IdleTimeout, streams well
// past the ceiling with no newline and no stall, and asserts the session is bounded+dropped FAST —
// far inside the idle timeout. Remove the LimitReader and the session blocks on the 30s idle timeout
// instead, so Dropped stays 0 in the window and this test fails (the old 64 KiB-vs-32 MiB test could
// not see that — only the deadline ever fired).
func TestSMTPNoNewlineIsBounded(t *testing.T) {
	l, err := smtpc.Listen("127.0.0.1:0", func(*smtpc.Message) {
		t.Error("a no-newline flood was delivered as a valid message")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.MaxBody = 4 << 10              // small ceiling the flood must trip
	l.IdleTimeout = 30 * time.Second // large, so only the size ceiling can end it in the window
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 256)
	_, _ = conn.Read(buf) // greeting

	// Stream well past MaxBody with NO newline and no stall (write in a goroutine so a blocked write
	// on a full socket buffer can't stall the test).
	flood := make([]byte, 16<<10)
	for i := range flood {
		flood[i] = 'x'
	}
	go func() { _, _ = conn.Write(flood) }()

	deadline := time.Now().Add(2 * time.Second) // ≪ the 30s idle timeout
	for l.Dropped() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if l.Dropped() < 1 {
		t.Error("a no-newline flood past MaxBody was not bounded by the size ceiling before the idle " +
			"timeout — the LimitReader is not doing the work")
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
