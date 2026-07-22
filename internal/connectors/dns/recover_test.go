package dns_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	dnsc "github.com/lucianoengel/openshield/internal/connectors/dns"
)

// ENG-2: the engine now parses attacker-controlled datagrams in-process. A panic in the sink (or
// parser) on one datagram must be CONTAINED — the listener drops it and keeps serving — never crash
// the process. A panicking sink stands in for a parser that panics on crafted bytes.
func TestDNSListenerRecoversFromSinkPanic(t *testing.T) {
	var delivered atomic.Int64
	l, err := dnsc.Listen("127.0.0.1:0", func(_ string, q dnsc.Query) {
		if q.Name == "boom.example" {
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

	client.Write(buildQuery("boom.example", 1)) // panics in the sink → must be recovered
	client.Write(buildQuery("good.example", 1)) // must still be delivered after the recover

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
