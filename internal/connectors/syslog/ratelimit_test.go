package syslog_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/limiter"
	"github.com/lucianoengel/openshield/internal/connectors/syslog"
)

// NIPS-7: a syslog flood beyond the admission rate is dropped BEFORE it mints pipeline events (and
// thus ledger writes), so a spoofed-source flood cannot grow the audit ledger at wire speed. With a
// burst of 1 and no refill, only the first of many datagrams reaches the sink; the rest are counted
// as rate-limited (observable, not silent).
func TestListenerRateLimitsFlood(t *testing.T) {
	var delivered atomic.Int64
	l, err := syslog.Listen("127.0.0.1:0", func(_ syslog.Message) { delivered.Add(1) }, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Burst 1, rate 0, frozen clock → exactly one datagram admitted, the rest rate-limited.
	lim := limiter.New(0, 1)
	lim.SetClock(func() time.Time { return time.Unix(1700000000, 0) })
	l.Limiter = lim

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()

	client, err := net.DialUDP("udp", nil, l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	msg := []byte(`<13>Feb  5 17:32:18 host myapp: exported a report`)
	for i := 0; i < 20; i++ {
		client.Write(msg)
	}

	deadline := time.Now().Add(2 * time.Second)
	for l.RateLimited() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if d := delivered.Load(); d != 1 {
		t.Errorf("delivered %d datagrams, want exactly 1 (the burst) — the flood was not rate-limited", d)
	}
	if l.RateLimited() < 1 {
		t.Errorf("rate-limited count = %d, want > 0 (the flood beyond the burst)", l.RateLimited())
	}
}

// ENG-2: the syslog connector parses attacker-controlled datagrams. A panic in the sink (or parser)
// on one datagram must be CONTAINED — the listener drops it and keeps serving — never crash the
// process. A panicking sink stands in for a parser that panics on crafted bytes.
func TestListenerRecoversFromSinkPanic(t *testing.T) {
	var delivered atomic.Int64
	l, err := syslog.Listen("127.0.0.1:0", func(m syslog.Message) {
		if m.Host == "boomhost" {
			panic("crafted input")
		}
		delivered.Add(1)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- l.Serve(ctx) }()

	client, err := net.DialUDP("udp", nil, l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	client.Write([]byte(`<13>Feb  5 17:32:18 boomhost myapp: boom`))  // panics in the sink → recovered
	client.Write([]byte(`<13>Feb  5 17:32:18 goodhost myapp: fine`)) // must still be delivered

	deadline := time.Now().Add(2 * time.Second)
	for delivered.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if delivered.Load() < 1 {
		t.Fatal("the listener did not survive a panicking datagram — a crafted input crashed the receive loop")
	}
	if l.Dropped() < 1 {
		t.Errorf("the panicking datagram was not counted as dropped")
	}
	cancel()
	if err := <-served; err != nil {
		t.Errorf("Serve = %v, want nil on clean shutdown", err)
	}
}
