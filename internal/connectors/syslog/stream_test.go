package syslog

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// THE STREAM TRANSPORT (D337): what UDP could not offer an audit path.
//
// These are unit-level because the framing rules are where an ingest quietly loses events, and framing is
// testable without a database. The transport's real claim — backpressure instead of silent kernel drop —
// is a property of TCP rather than of this code, so it is stated in the spec and not asserted here.

// streamFixture starts a listener on an ephemeral port and collects what it parses.
func streamFixture(t *testing.T) (addr string, got func() []Message, l *StreamListener) {
	t.Helper()
	var mu sync.Mutex
	var msgs []Message
	l, err := ListenStream("127.0.0.1:0", func(m Message) {
		mu.Lock()
		msgs = append(msgs, m)
		mu.Unlock()
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = l.Serve(ctx) }()
	return l.Addr().String(), func() []Message {
		mu.Lock()
		defer mu.Unlock()
		return append([]Message(nil), msgs...)
	}, l
}

func send(t *testing.T, addr string, payload string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io_WriteString(c, payload); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // let the reader drain before the close
}

func io_WriteString(c net.Conn, s string) (int, error) { return c.Write([]byte(s)) }

const rfc5424 = `<134>1 2026-07-28T10:00:00Z fw01 app - - - CEF:0|V|P|1.0|100|Blocked|5|src=203.0.113.9`

// TestBothFramingsAreAccepted is the interoperability claim, and it is not a nicety: real senders use
// both — rsyslog defaults to one, many appliances to the other — and requiring a single framing is how a
// log source ends up NOT ONBOARDED. An un-ingested source produces no alerts and looks exactly like a
// quiet one.
func TestBothFramingsAreAccepted(t *testing.T) {
	addr, got, _ := streamFixture(t)

	// Newline-terminated, then octet-counted, on the same connection — a sender may mix them, so framing
	// is decided per message rather than per connection.
	octet := fmt.Sprintf("%d %s", len(rfc5424), rfc5424)
	send(t, addr, rfc5424+"\n"+octet)

	if n := len(got()); n != 2 {
		t.Fatalf("got %d messages, want 2 (one per framing): %+v", n, got())
	}
	for i, m := range got() {
		if !strings.Contains(m.Msg, "CEF:0") {
			t.Errorf("message %d did not carry its payload: %q", i, m.Msg)
		}
	}
}

// TestAnOversizedMessageIsRefusedNotTruncated.
//
// This is the difference the stream transport makes. Over a datagram the kernel truncates before the
// application has a say, and the result surfaces as a mystery parse failure — so the events most likely
// to be lost are the RICH ones, which are the interesting ones. Over a stream the receiver says no, and
// says how big it was.
func TestAnOversizedMessageIsRefusedNotTruncated(t *testing.T) {
	addr, got, l := streamFixture(t)

	huge := "<134>1 2026-07-28T10:00:00Z fw01 app - - - " + strings.Repeat("A", maxLine+1024)
	send(t, addr, fmt.Sprintf("%d %s", len(huge), huge)+"\n"+rfc5424+"\n")

	if l.Oversize() != 1 {
		t.Errorf("Oversize() = %d, want 1 — an over-bound message must be REPORTED as too large, not "+
			"left to surface as an unexplained parse failure", l.Oversize())
	}
	// No partial event, and the connection carried on to the good message that followed.
	msgs := got()
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1 (the oversized one must not be stored, whole or in part): %+v",
			len(msgs), msgs)
	}
	if strings.Contains(msgs[0].Msg, "AAAA") {
		t.Error("a prefix of the oversized message was ingested — truncation is what this transport exists to avoid")
	}
}

// TestAMalformedMessageDoesNotEndTheStream.
//
// One device sending one bad line must never stop the estate's feed. That includes the ambiguous case
// the auto-detected framing creates: a newline-framed message that merely BEGINS with a digit looks like
// an octet count until the number fails to parse.
func TestAMalformedMessageDoesNotEndTheStream(t *testing.T) {
	addr, got, l := streamFixture(t)

	send(t, addr, "2026-07-28 this begins with a digit and is not octet-counted\n"+
		"not a syslog line at all\n"+
		rfc5424+"\n")

	msgs := got()
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1 — the valid message after two malformed ones must still be "+
			"ingested, or one bad sender stops the feed: %+v", len(msgs), msgs)
	}
	if l.Dropped() < 2 {
		t.Errorf("Dropped() = %d, want at least 2 — a message that cannot be parsed must be COUNTED, "+
			"or an estate cannot tell a silent device from an unreadable one", l.Dropped())
	}
}

// TestTheConnectionCapRefusesRatherThanQueues: a stream listener holds resources a datagram one does not.
func TestTheConnectionCapRefusesRatherThanQueues(t *testing.T) {
	var mu sync.Mutex
	var n int
	l, err := ListenStream("127.0.0.1:0", func(Message) { mu.Lock(); n++; mu.Unlock() }, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.MaxConns = 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()

	held, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	time.Sleep(200 * time.Millisecond)

	// The second connection is accepted by the kernel and then closed by us — the sender sees a closed
	// connection and retries, which IS the backpressure. Queueing it forever would reproduce the
	// unbounded-buffer failure in userspace.
	second, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	time.Sleep(300 * time.Millisecond)
	_, _ = second.Write([]byte(rfc5424 + "\n"))
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if n != 0 {
		t.Errorf("a connection past the cap was served (%d messages) — the cap must refuse, or the "+
			"listener has no bound at all", n)
	}
}
