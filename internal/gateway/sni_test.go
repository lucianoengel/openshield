package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// clientHelloFor returns the raw bytes of a TLS ClientHello for the given server name, captured by
// running a real tls.Client handshake against a recording pipe (no network, no real server).
func clientHelloFor(t *testing.T, serverName string) []byte {
	t.Helper()
	cconn, sconn := net.Pipe()
	defer cconn.Close()
	defer sconn.Close()

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := sconn.Read(buf) // the first flight is the ClientHello
		got <- append([]byte(nil), buf[:n]...)
	}()

	client := tls.Client(cconn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	_ = cconn.SetDeadline(time.Now().Add(time.Second))
	go client.Handshake() // will stall after sending the ClientHello (server never replies)

	select {
	case b := <-got:
		return b
	case <-time.After(2 * time.Second):
		t.Fatal("did not capture a ClientHello")
		return nil
	}
}

func TestExtractSNI(t *testing.T) {
	hello := clientHelloFor(t, "evil.example.com")
	if got := extractSNI(hello); got != "evil.example.com" {
		t.Fatalf("extractSNI = %q, want evil.example.com", got)
	}

	// Not a TLS handshake record.
	if got := extractSNI([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); got != "" {
		t.Errorf("non-TLS buffer yielded SNI %q, want empty", got)
	}
	// Empty / tiny buffers.
	if extractSNI(nil) != "" || extractSNI([]byte{22}) != "" {
		t.Error("tiny buffer must yield empty, no panic")
	}
	// A hard-truncated ClientHello (cut well before the extensions) must not panic and yields empty.
	if got := extractSNI(hello[:15]); got != "" {
		t.Errorf("a hard-truncated ClientHello yielded %q, want empty (no over-read/panic)", got)
	}
	// Truncating one byte at a time must never panic, whatever the cut point.
	for i := 0; i <= len(hello); i++ {
		_ = extractSNI(hello[:i])
	}
	// An attacker-crafted ClientHello that reaches the extensions and declares an extension whose
	// length overruns the buffer must return empty and MUST NOT over-read/panic (the bounds check).
	if got := extractSNI(craftedHelloWithHugeExt()); got != "" {
		t.Errorf("a ClientHello with an overrunning extension length yielded %q, want empty (no over-read)", got)
	}
}

// craftedHelloWithHugeExt builds a well-formed ClientHello up to the extensions, then a single
// extension whose declared length (0xFFFF) runs far past the buffer — the exact input the
// extension bounds check exists to reject.
func craftedHelloWithHugeExt() []byte {
	body := []byte{0x03, 0x03} // client version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id length 0
	body = append(body, 0x00, 0x02, 0xc0, 0x2f) // cipher suites: len 2 + one suite
	body = append(body, 0x01, 0x00)             // compression: len 1 + null
	// extensions: total length 4 (one ext header), then an ext claiming 0xFFFF bytes of data.
	body = append(body, 0x00, 0x04) // ext_total = 4
	body = append(body, 0x00, 0x2a) // ext type 0x002a (arbitrary, not server_name)
	body = append(body, 0xff, 0xff) // ext len 0xFFFF — overruns
	// handshake header: type 1 + 3-byte length.
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	// record header: type 22, version 0x0301, 2-byte length.
	rec := []byte{22, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// TestHandleFlowBlocksBySNI: a flow whose ClientHello SNI is denied is dropped, even though the
// decider would allow it on metadata.
//
// Mutation (the decider ignores hint.SNI): the denied SNI is not blocked → this test FAILs.
func TestHandleFlowBlocksBySNI(t *testing.T) {
	origin := newEchoServer(t)
	client, peer := clientPair()
	defer peer.Close()

	decide := func(_ context.Context, _ net.Addr, _ net.Addr, h FlowHint) (bool, error) {
		return h.SNI == "blocked.example.com", nil // block by SNI only
	}
	go handleFlow(context.Background(), client, origin.ln.Addr(), decide, dialTo(origin.ln.Addr()), nil)

	blockedHello := clientHelloFor(t, "blocked.example.com")
	go func() { _, _ = peer.Write(blockedHello) }()

	// The flow is dropped: the origin receives nothing and the client is closed.
	select {
	case <-origin.gotBytes:
		t.Fatal("the origin received the handshake — a flow with a blocked SNI must be dropped")
	case <-time.After(700 * time.Millisecond):
	}
}

// TestHandleFlowReplaysPeekedBytes: an allowed flow's peeked ClientHello reaches the origin (the
// bytes the client sent first are replayed), so the flow is byte-for-byte transparent.
//
// Mutation (handleFlow does not replay the peeked prefix): the origin never sees the handshake →
// this test FAILs.
func TestHandleFlowReplaysPeekedBytes(t *testing.T) {
	// An origin that records the first chunk it receives.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	firstChunk := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		firstChunk <- append([]byte(nil), buf[:n]...)
	}()

	client, peer := clientPair()
	defer peer.Close()
	decide := func(context.Context, net.Addr, net.Addr, FlowHint) (bool, error) { return false, nil } // allow
	go handleFlow(context.Background(), client, ln.Addr(), decide, dialTo(ln.Addr()), nil)

	hello := clientHelloFor(t, "allowed.example.com")
	go peer.Write(hello)

	select {
	case got := <-firstChunk:
		if !bytes.HasPrefix(hello, got[:min(len(got), 8)]) && !bytes.Contains(hello, got) {
			t.Fatalf("the origin's first bytes are not the client's peeked handshake")
		}
		if extractSNI(got) != "allowed.example.com" {
			t.Fatalf("the replayed bytes did not carry the original ClientHello (SNI=%q)", extractSNI(got))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the origin never received the replayed handshake bytes")
	}
}

// TestHandleFlowPeekTimeoutFailsOpen: a client that sends nothing before the peek deadline is not
// dropped — the peek times out, the flow decides on metadata (allow) and later bytes splice through.
func TestHandleFlowPeekTimeoutFailsOpen(t *testing.T) {
	origin := newEchoServer(t)
	client, peer := clientPair()
	defer peer.Close()

	sawSNI := make(chan string, 1)
	decide := func(_ context.Context, _ net.Addr, _ net.Addr, h FlowHint) (bool, error) {
		sawSNI <- h.SNI
		return false, nil // allow
	}
	go handleFlow(context.Background(), client, origin.ln.Addr(), decide, dialTo(origin.ln.Addr()), nil)

	// Do NOT write until after the peek deadline; the decision must proceed with an empty SNI.
	select {
	case s := <-sawSNI:
		if s != "" {
			t.Fatalf("expected empty SNI on a peek timeout, got %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the decision never ran after the peek timeout (the peek did not fail open)")
	}
	// After the timeout, bytes still splice through (not dropped).
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	peer.Write([]byte("late"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("post-timeout flow did not splice (fail-open broken): %v", err)
	}
}
