package dns_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	dnsc "github.com/lucianoengel/openshield/internal/connectors/dns"
	"github.com/lucianoengel/openshield/internal/connectors/limiter"
)

// NIPS-7: a query flood beyond the admission rate is dropped BEFORE it mints pipeline events (and
// thus ledger writes), so a spoofed-source flood cannot grow the audit ledger at wire speed. With a
// burst of 1 and no refill, only the first of many datagrams reaches the sink.
func TestDNSListenerRateLimitsFlood(t *testing.T) {
	var delivered atomic.Int64
	l, err := dnsc.Listen("127.0.0.1:0", func(_ string, _ dnsc.Query) { delivered.Add(1) }, nil)
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
	for i := 0; i < 20; i++ {
		client.Write(buildQuery("flood.example", 1))
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
