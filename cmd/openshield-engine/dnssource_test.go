package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// buildQueryPacket assembles a minimal standard DNS query datagram (mirrors the connector's
// own test builder — an unexported helper is not importable across packages).
func buildQueryPacket(name string, qtype uint16) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)
	msg = append(msg, byte(qtype>>8), byte(qtype))
	msg = append(msg, 0x00, 0x01)
	return msg
}

// The DNS source wiring turns a real UDP query into a NetworkSubject Event on the engine's
// event channel — the connector→pipeline link (NIPS-3). The queried name must reach SniHost
// (the metadata a policy decides on) and the datagram's source IP must reach SrcIp (a network
// decision must know who asked). This is the end-to-end proof that the built-but-unwired DNS
// listener now feeds the pipeline.
func TestDNSSourceProducesNetworkEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan *corev1.Event, 4)

	l, err := dnsListener(ctx, "127.0.0.1:0", events, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = l.Serve(ctx) }()

	client, err := net.DialUDP("udp", nil, l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.Write(buildQueryPacket("secret.exfil.example", 16))

	select {
	case ev := <-events:
		if ev.GetConnectorId() != "dns" {
			t.Errorf("connector = %q, want dns", ev.GetConnectorId())
		}
		if ev.GetKind() != corev1.EventKind_EVENT_KIND_DNS_QUERY {
			t.Errorf("kind = %v, want DNS_QUERY", ev.GetKind())
		}
		if host := ev.GetNetwork().GetSniHost(); host != "secret.exfil.example" {
			t.Errorf("sni_host = %q, want the queried name", host)
		}
		if ip := ev.GetNetwork().GetSrcIp(); ip != "127.0.0.1" {
			t.Errorf("src_ip = %q, want 127.0.0.1 (the loopback client) — the source must reach the Event", ip)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Event produced from the DNS query — the connector is not wired to the pipeline")
	}
}
