package smtp_test

import (
	"bufio"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/smtp"
)

// SMTP FILTERING — the NIPS gap the README named: "SMTP is captured and inspected, not filtered —
// nothing is blocked on the mail path."
//
// Mail is the exfil channel a DLP product exists to cover, and inspection that cannot refuse is a report
// written after the data left. The only moment SMTP offers to refuse a message is the reply to the final
// "." of DATA: after that the client considers it accepted, so a verdict reached later can report but not
// prevent. These tests drive a real client dialogue against a real listener and assert the CODE it gets.

// session runs one SMTP conversation and returns every server reply, in order.
func dialSession(t *testing.T, addr string, body string) []string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(conn)
	var replies []string
	read := func() string {
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			return ""
		}
		line = strings.TrimRight(line, "\r\n")
		replies = append(replies, line)
		return line
	}
	send := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }

	read() // 220 greeting
	send("EHLO test")
	read()
	send("MAIL FROM:<alice@corp.example>")
	read()
	send("RCPT TO:<bob@partner.example>")
	read()
	send("DATA")
	read() // 354
	send("Subject: quarterly\r\n\r\n" + body + "\r\n.")
	read() // THE VERDICT
	send("QUIT")
	read()
	return replies
}

// startListener returns the listener and a COUNTER FUNCTION rather than the captured slice itself.
// Returning the slice returns its header by value — a snapshot taken before the sink ever appends — so
// the caller would read zero forever and the assertion would be about the copy, not the capture.
func startListener(t *testing.T, decide func(*smtp.Message) bool) (*smtp.Listener, func() int) {
	t.Helper()
	var mu sync.Mutex
	var captured []*smtp.Message

	l, err := smtp.Listen("127.0.0.1:0", func(m *smtp.Message) {
		mu.Lock()
		defer mu.Unlock()
		captured = append(captured, m)
	}, slog.New(slog.NewTextHandler(discard{}, nil)))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	l.Decide = decide
	go func() { _ = l.Serve(t.Context()) }()
	return l, func() int { mu.Lock(); defer mu.Unlock(); return len(captured) }
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// THE HEADLINE: a message the policy refuses gets a 5xx, not a 250.
func TestARefusedMessageIsRejectedAtEndOfData(t *testing.T) {
	l, _ := startListener(t, func(m *smtp.Message) bool {
		return strings.Contains(string(m.Body), "CPF")
	})

	replies := dialSession(t, l.Addr().String(), "CPF 529.982.247-25")
	verdict := replies[len(replies)-2] // the reply to "." (QUIT's 221 is last)

	if !strings.HasPrefix(verdict, "550") {
		t.Fatalf("the message was ACCEPTED (%q) — inspection that cannot refuse is a report written "+
			"after the data left; the reply to the final '.' is the only moment SMTP offers to say no",
			verdict)
	}
	if got := l.Rejected(); got != 1 {
		t.Errorf("Rejected() = %d, want 1", got)
	}
}

// And a clean message still goes through: a filter that refuses everything is not a filter, it is an
// outage. This is the direction the deny tests cannot prove.
func TestACleanMessageIsStillAccepted(t *testing.T) {
	l, _ := startListener(t, func(m *smtp.Message) bool {
		return strings.Contains(string(m.Body), "CPF")
	})

	replies := dialSession(t, l.Addr().String(), "lunch at one")
	verdict := replies[len(replies)-2]

	if !strings.HasPrefix(verdict, "250") {
		t.Fatalf("a clean message was refused (%q) — a filter that blocks everything is an outage", verdict)
	}
	if got := l.Rejected(); got != 0 {
		t.Errorf("Rejected() = %d, want 0", got)
	}
}

// NIL Decide IS THE DEFAULT AND MUST CHANGE NOTHING (D1, observe-only). Every existing deployment keeps
// capturing and accepting; filtering is opt-in like every other enforcer.
func TestWithNoDecideHookEverythingIsAcceptedAndCaptured(t *testing.T) {
	l, capturedCount := startListener(t, nil)

	replies := dialSession(t, l.Addr().String(), "CPF 529.982.247-25")
	verdict := replies[len(replies)-2]

	if !strings.HasPrefix(verdict, "250") {
		t.Fatalf("a listener with no Decide hook refused a message (%q); filtering must be opt-in", verdict)
	}
	if got := l.Rejected(); got != 0 {
		t.Errorf("Rejected() = %d, want 0 with no hook", got)
	}
	waitFor(t, func() bool { return capturedCount() == 1 })
}

// THE MESSAGE IS HANDLED ONCE. Decide runs the full pipeline to reach its verdict, so also invoking the
// sink would put one message through classify → policy → audit twice: two ledger entries and two alerts
// for one email.
func TestADecidedMessageIsNotAlsoDeliveredToTheSink(t *testing.T) {
	var decides int
	var mu sync.Mutex
	l, capturedCount := startListener(t, func(*smtp.Message) bool {
		mu.Lock()
		defer mu.Unlock()
		decides++
		return false
	})

	_ = dialSession(t, l.Addr().String(), "hello")
	time.Sleep(300 * time.Millisecond) // give any stray sink call time to land

	mu.Lock()
	gotDecides := decides
	mu.Unlock()
	gotSink := capturedCount()

	if gotDecides != 1 {
		t.Fatalf("Decide ran %d times, want 1", gotDecides)
	}
	if gotSink != 0 {
		t.Fatalf("the sink ALSO received the message (%d times) — it would be classified, decided and "+
			"audited twice, so one email produces two ledger entries and two alerts", gotSink)
	}
}

// An unparseable session is COUNTED AND ACCEPTED, never refused. Refusing what we failed to understand
// would make a parser bug look like a policy decision to the sender.
func TestAnUnparseableSessionIsAcceptedNotRefused(t *testing.T) {
	l, _ := startListener(t, func(*smtp.Message) bool { return true }) // would refuse anything parseable

	conn, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	_, _ = br.ReadString('\n') // greeting

	// DATA with no MAIL FROM / RCPT TO: ParseSession cannot build a message from this.
	_, _ = conn.Write([]byte("DATA\r\n"))
	_, _ = br.ReadString('\n') // 354
	_, _ = conn.Write([]byte("body\r\n.\r\n"))
	verdict, _ := br.ReadString('\n')

	if strings.HasPrefix(verdict, "550") {
		t.Fatalf("an unparseable session was REFUSED (%q); a parser failure must not reach the sender as "+
			"a policy decision", strings.TrimSpace(verdict))
	}
	if got := l.Rejected(); got != 0 {
		t.Errorf("Rejected() = %d, want 0 — nothing was refused by policy here", got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within the deadline")
}
