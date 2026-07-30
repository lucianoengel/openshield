package printguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// serve starts a Server on a temp socket and returns its path. It fails the test if the listener never
// comes up, rather than letting the first Ask fail with a confusing dial error.
func serve(t *testing.T, decide func(context.Context, Request) (Verdict, error)) string {
	t.Helper()
	sock := socketPath(t, "pg.sock")
	s := &Server{Decide: decide, ReadTimeout: 5 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Listen(ctx, sock) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not return after cancellation")
		}
	})
	waitForSocket(t, sock)
	if got := s.Addr(); got != sock {
		t.Fatalf("Addr() = %q, want %q", got, sock)
	}
	return sock
}

func waitForSocket(t *testing.T, sock string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", sock); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("socket %s never accepted a connection", sock)
}

func TestVerdictReachesTheFilter(t *testing.T) {
	for _, want := range []Verdict{VerdictAllow, VerdictDeny} {
		t.Run(fmt.Sprintf("verdict-%d", want), func(t *testing.T) {
			sock := serve(t, func(_ context.Context, _ Request) (Verdict, error) { return want, nil })
			got, err := Ask(sock, Request{ID: 1, Printer: "p", User: "u", Job: []byte("doc")}, 5*time.Second)
			if err != nil {
				t.Fatalf("Ask: %v", err)
			}
			if got != want {
				t.Fatalf("got verdict %d, want %d", got, want)
			}
		})
	}
}

func TestTheServerSeesWhatTheFilterSent(t *testing.T) {
	var (
		mu   sync.Mutex
		seen Request
	)
	sock := serve(t, func(_ context.Context, r Request) (Verdict, error) {
		mu.Lock()
		defer mu.Unlock()
		seen = r
		return VerdictDeny, nil
	})
	sent := Request{ID: 0xDEADBEEF, Printer: "Front_Desk", User: "bob", HasTitle: true, Job: []byte("secret memo")}
	if _, err := Ask(sock, sent, 5*time.Second); err != nil {
		t.Fatalf("Ask: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen.ID != sent.ID || seen.Printer != sent.Printer || seen.User != sent.User || seen.HasTitle != sent.HasTitle || string(seen.Job) != string(sent.Job) {
		t.Fatalf("server saw %+v, filter sent %+v", seen, sent)
	}
}

// The claim in Server.handle is that an evaluation failure is DROPPED rather than answered, because an
// "allow" response would be indistinguishable from a real decision to allow. The filter still ends up
// allowing the job — that is the documented fail-open — but it must get there via an ERROR, so the failure
// is visible and auditable rather than laundered into a verdict.
func TestAnEvaluationFailureIsAnErrorNotAnAllow(t *testing.T) {
	boom := errors.New("classifier unavailable")
	sock := serve(t, func(_ context.Context, _ Request) (Verdict, error) { return VerdictDeny, boom })

	v, err := Ask(sock, Request{ID: 1}, 5*time.Second)
	if err == nil {
		t.Fatal("Ask returned no error for a failed evaluation — the filter cannot tell a broken engine from a decision to allow")
	}
	if v != VerdictAllow {
		t.Fatalf("got verdict %d on error; the filter's fail-open contract needs allow", v)
	}
}

func TestAMismatchedResponseIDIsRefused(t *testing.T) {
	// A server that answers job A with job B's verdict. Accepting it would apply one document's decision to
	// another — wrong in both directions, and invisible.
	sock := socketPath(t, "ct.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := ReadRequest(conn)
		if err != nil {
			return
		}
		_ = WriteResponse(conn, Response{ID: req.ID + 1, Verdict: VerdictDeny})
	}()

	v, err := Ask(sock, Request{ID: 100}, 5*time.Second)
	if !errors.Is(err, ErrIDMismatch) {
		t.Fatalf("got %v, want ErrIDMismatch", err)
	}
	if v != VerdictAllow {
		t.Fatalf("got verdict %d, want allow alongside the error", v)
	}
}

func TestAskFailsOpenWhenNothingIsListening(t *testing.T) {
	v, err := Ask(socketPath(t, "absent.sock"), Request{ID: 1}, time.Second)
	if err == nil {
		t.Fatal("dialing an absent socket returned no error")
	}
	if v != VerdictAllow {
		t.Fatalf("got verdict %d, want allow", v)
	}
}

func TestAskRejectsAJobItCannotEncode(t *testing.T) {
	sock := serve(t, func(_ context.Context, _ Request) (Verdict, error) { return VerdictDeny, nil })
	v, err := Ask(sock, Request{ID: 1, Job: make([]byte, MaxJobBytes+1)}, 5*time.Second)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	if v != VerdictAllow {
		t.Fatalf("got verdict %d, want allow", v)
	}
}

// A restart after an unclean shutdown leaves the socket file behind. If Listen did not remove it, bind
// would fail with EADDRINUSE and print control would be silently absent for the life of the process.
func TestAStaleSocketDoesNotWedgeARestart(t *testing.T) {
	sock := socketPath(t, "stale.sock")

	first, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	// Close the listener WITHOUT unlinking, the way a killed process leaves things.
	if ul, ok := first.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("test setup: expected a stale socket file: %v", err)
	}

	// Bind the real server against the stale path directly — serve() would allocate a fresh one.
	s := &Server{Decide: func(context.Context, Request) (Verdict, error) { return VerdictDeny, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Listen(ctx, sock) }()
	waitForSocket(t, sock)

	got, err := Ask(sock, Request{ID: 1}, 5*time.Second)
	if err != nil {
		t.Fatalf("Ask after restart over a stale socket: %v", err)
	}
	if got != VerdictDeny {
		t.Fatalf("got %d, want deny", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not return")
	}
}

func TestListenRefusesToStartWithoutADecider(t *testing.T) {
	err := (&Server{}).Listen(context.Background(), socketPath(t, "x.sock"))
	if err == nil {
		t.Fatal("a server with no Decide func started anyway — it would accept jobs and answer nothing")
	}
}

// A garbage frame must cost the server one dropped connection, not the listener.
func TestAGarbageFrameDoesNotKillTheServer(t *testing.T) {
	sock := serve(t, func(_ context.Context, _ Request) (Verdict, error) { return VerdictDeny, nil })

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("not a frame at all")); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	got, err := Ask(sock, Request{ID: 2}, 5*time.Second)
	if err != nil {
		t.Fatalf("server stopped serving after a garbage frame: %v", err)
	}
	if got != VerdictDeny {
		t.Fatalf("got %d, want deny", got)
	}
}
