package syslog_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/syslog"
)

// The runnable listener over a REAL UDP socket: a valid datagram arrives parsed; a
// malformed datagram is dropped and counted, and ingest keeps running.
func TestListenerReceivesAndSurvivesGarbage(t *testing.T) {
	var mu sync.Mutex
	var got []syslog.Message
	l, err := syslog.Listen("127.0.0.1:0", func(m syslog.Message) {
		mu.Lock()
		got = append(got, m)
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

	// One valid message, one garbage datagram (no priority).
	client.Write([]byte(`<13>Feb  5 17:32:18 host myapp: exported a report`))
	client.Write([]byte(`this is not a syslog line`))
	client.Write([]byte(`<34>1 2003-10-11T22:14:15Z m su - - - login ok`))

	// Wait for the two valid messages to be delivered.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("received %d messages, want 2", n)
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	hosts := []string{got[0].Host, got[1].Host}
	mu.Unlock()
	if hosts[0] != "host" && hosts[1] != "host" {
		t.Errorf("expected a message from host 'host', got %v", hosts)
	}

	// The garbage datagram was dropped, not delivered, and ingest survived.
	// (Give the drop a moment to register.)
	time.Sleep(50 * time.Millisecond)
	if l.Dropped() < 1 {
		t.Errorf("dropped = %d, want at least 1 (the garbage datagram)", l.Dropped())
	}

	cancel()
	if err := <-served; err != nil {
		t.Errorf("Serve returned %v, want nil on clean shutdown", err)
	}
}

func TestListenNilSink(t *testing.T) {
	if _, err := syslog.Listen("127.0.0.1:0", nil, nil); err == nil {
		t.Error("Listen accepted a nil sink")
	}
}
