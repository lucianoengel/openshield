package gateway

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// echoServer accepts one connection and echoes bytes back until the peer closes. It returns
// its listen address and records whether it received ANY bytes.
type echoServer struct {
	ln       net.Listener
	gotBytes chan bool
}

func newEchoServer(t *testing.T) *echoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &echoServer{ln: ln, gotBytes: make(chan bool, 1)}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		n, _ := conn.Read(buf)
		if n > 0 {
			select {
			case e.gotBytes <- true:
			default:
			}
			conn.Write(buf[:n]) // echo
			io.Copy(conn, conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return e
}

// clientPair returns two ends of an in-memory connection: the "client" the handler sees, and
// the "peer" the test drives.
func clientPair() (handlerSide, testSide net.Conn) { return net.Pipe() }

func dialTo(addr net.Addr) DialFunc {
	return func(net.Addr) (net.Conn, error) { return net.Dial("tcp", addr.String()) }
}

// TestHandleFlowDrops: a block decision closes the client and NO bytes reach the origin.
//
// Mutation (handleFlow ignores block, always splices): the origin receives the client's bytes
// → this test FAILs.
func TestHandleFlowDrops(t *testing.T) {
	origin := newEchoServer(t)
	client, peer := clientPair()
	defer peer.Close()

	decide := func(context.Context, net.Addr, net.Addr, FlowHint) (bool, error) { return true, nil } // BLOCK
	go handleFlow(context.Background(), client, origin.ln.Addr(), decide, dialTo(origin.ln.Addr()), nil)

	// The client end should be closed by the handler (drop); a write then read returns EOF/err.
	peer.SetDeadline(time.Now().Add(time.Second))
	_, _ = peer.Write([]byte("x"))
	buf := make([]byte, 1)
	if _, err := peer.Read(buf); err == nil {
		t.Fatal("client connection was not closed — a blocked flow must be dropped")
	}
	select {
	case <-origin.gotBytes:
		t.Fatal("the origin received bytes — a blocked flow must not reach the destination")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestHandleFlowSplices: an allow decision connects the flow to the origin, both directions.
func TestHandleFlowSplices(t *testing.T) {
	origin := newEchoServer(t)
	client, peer := clientPair()
	defer peer.Close()

	decide := func(context.Context, net.Addr, net.Addr, FlowHint) (bool, error) { return false, nil } // ALLOW
	go handleFlow(context.Background(), client, origin.ln.Addr(), decide, dialTo(origin.ln.Addr()), nil)

	peer.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := peer.Read(buf); err != nil {
		t.Fatalf("no echo returned through the splice: %v", err)
	}
	if buf[0] != 'y' {
		t.Fatalf("echo = %q, want 'y'", buf[0])
	}
	select {
	case <-origin.gotBytes:
	case <-time.After(time.Second):
		t.Fatal("the origin never received the client's bytes")
	}
}

// TestHandleFlowFailOpen: a decide ERROR forwards the flow (splice), not drop — egress fail-open.
//
// Mutation (handleFlow treats a decide error as block / fail-closed): the origin gets no bytes and
// the echo never returns → this test FAILs.
func TestHandleFlowFailOpen(t *testing.T) {
	origin := newEchoServer(t)
	client, peer := clientPair()
	defer peer.Close()

	decide := func(context.Context, net.Addr, net.Addr, FlowHint) (bool, error) {
		return true, io.ErrUnexpectedEOF // block=true BUT an error → must be treated as ALLOW (fail-open)
	}
	go handleFlow(context.Background(), client, origin.ln.Addr(), decide, dialTo(origin.ln.Addr()), nil)

	peer.SetDeadline(time.Now().Add(2 * time.Second))
	peer.Write([]byte("z"))
	buf := make([]byte, 1)
	if _, err := peer.Read(buf); err != nil {
		t.Fatalf("fail-open did not splice the flow (egress broken on a detection error): %v", err)
	}
	if buf[0] != 'z' {
		t.Fatalf("echo = %q, want 'z'", buf[0])
	}
}
