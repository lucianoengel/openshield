package dns_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	dnsc "github.com/lucianoengel/openshield/internal/connectors/dns"
)

// NIPS-3: the DNS listener receives real UDP query datagrams, parses them to the sink, and
// survives garbage (dropped + counted) — the DNS parser is now runnable.
func TestDNSListenerReceivesAndSurvivesGarbage(t *testing.T) {
	var mu sync.Mutex
	var got []dnsc.Query
	var srcIPs []string
	l, err := dnsc.Listen("127.0.0.1:0", func(srcIP string, q dnsc.Query) {
		mu.Lock()
		got = append(got, q)
		srcIPs = append(srcIPs, srcIP)
		mu.Unlock()
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

	client.Write(buildQuery("secret.exfil.example", 16)) // a real TXT query
	client.Write([]byte("not a dns packet"))             // garbage
	client.Write(buildQuery("www.example.com", 1))       // a real A query

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("received %d queries, want 2", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	names := []string{got[0].Name, got[1].Name}
	gotIPs := append([]string(nil), srcIPs...)
	mu.Unlock()
	found := false
	for _, nm := range names {
		if nm == "secret.exfil.example" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the exfil query name, got %v", names)
	}
	// The source IP must reach the sink — a loopback client dials from 127.0.0.1.
	for _, ip := range gotIPs {
		if ip != "127.0.0.1" {
			t.Errorf("source IP = %q, want 127.0.0.1 (the loopback client)", ip)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if l.Dropped() < 1 {
		t.Errorf("dropped = %d, want >= 1 (the garbage datagram)", l.Dropped())
	}
	cancel()
	if err := <-served; err != nil {
		t.Errorf("Serve = %v, want nil on clean shutdown", err)
	}
}

func TestDNSListenNilSink(t *testing.T) {
	if _, err := dnsc.Listen("127.0.0.1:0", nil, nil); err == nil {
		t.Error("Listen accepted a nil sink")
	}
}
