package smtp_test

import (
	"context"
	"net/smtp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	smtpc "github.com/lucianoengel/openshield/internal/connectors/smtp"
)

// TestSMTPListenerRecoversFromSinkPanic (ENG-2): a panic while handling ONE session — here induced in
// the sink, the seam a real crafted-message parser panic would surface through — must be CONTAINED
// (dropped + counted) and MUST NOT crash the listener that hosts it. The existing drop test covers a
// malformed session that never reaches the sink; this drives the recover on the deliver→sink path.
//
// Mutation: removing the `recover()` in Listener.handle lets the first session's panic escape its
// goroutine, which crashes the whole test binary (an unrecovered goroutine panic terminates the
// process) — so this test cannot pass without the recover.
func TestSMTPListenerRecoversFromSinkPanic(t *testing.T) {
	var calls atomic.Int64
	var mu sync.Mutex
	var captured int
	l, err := smtpc.Listen("127.0.0.1:0", func(*smtpc.Message) {
		// Panic on the FIRST delivered message only, so a second session can prove the listener survived.
		if calls.Add(1) == 1 {
			panic("simulated panic parsing a crafted session")
		}
		mu.Lock()
		captured++
		mu.Unlock()
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()

	addr := l.Addr().String()
	body := "Subject: x\r\n\r\nhello\r\n"
	send := func() {
		if err := smtp.SendMail(addr, nil, "a@corp.example", []string{"b@partner.example"}, []byte(body)); err != nil {
			t.Fatalf("SendMail: %v", err)
		}
	}

	// First session → the sink panics → the recover must contain it (dropped++), never crash the host.
	send()
	deadline := time.Now().Add(3 * time.Second)
	for l.Dropped() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if l.Dropped() < 1 {
		t.Fatal("a session whose handling panicked was not counted as dropped — the recover did not fire")
	}

	// Second session → the listener is still alive and serving → the message is delivered.
	send()
	for time.Now().Before(deadline) {
		mu.Lock()
		n := captured
		mu.Unlock()
		if n >= 1 {
			return // listener survived the panic and kept serving
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the listener did not serve a second session after recovering from a panic — the panic was not contained")
}
