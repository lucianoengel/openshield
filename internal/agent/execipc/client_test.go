package execipc_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/execipc"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// stubServer is a hand-rolled peer so a test can misbehave in ways the real server never would — answer
// the wrong id, hang, close mid-frame. handle is called per request and returns the response to send;
// returning shouldClose ends the connection instead.
type stubServer struct {
	socket string
	ln     net.Listener
	calls  atomic.Int64

	connMu sync.Mutex
	conns  []net.Conn

	handle func(req execipc.Request) (resp execipc.Response, shouldClose bool)
}

func newStubServer(t *testing.T, handle func(execipc.Request) (execipc.Response, bool)) *stubServer {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "exec.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	s := &stubServer{socket: socket, ln: ln, handle: handle}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *stubServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.connMu.Lock()
		s.conns = append(s.conns, conn)
		s.connMu.Unlock()
		go func() {
			defer conn.Close()
			for {
				req, err := execipc.ReadRequest(conn)
				if err != nil {
					return
				}
				s.calls.Add(1)
				resp, closeIt := s.handle(req)
				if closeIt {
					return
				}
				if err := execipc.WriteResponse(conn, resp); err != nil {
					return
				}
			}
		}()
	}
}

// stop closes the listener AND every accepted connection. Closing only the listener leaves established
// connections serving, which is not what an engine restart looks like — the first version of the restart
// test passed for that reason and proved nothing.
func (s *stubServer) stop() {
	_ = s.ln.Close()
	s.connMu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
	s.connMu.Unlock()
}

func newTestClient(socket string) *execipc.Client {
	c := execipc.NewClient(socket)
	c.Timeout = 150 * time.Millisecond
	c.CacheTTL = 0 // most tests want every call to hit the wire; the cache has its own test
	c.BreakerThreshold = 3
	c.BreakerCooldown = 200 * time.Millisecond
	return c
}

// TestClientAppliesDenyAndAllow: the basic contract — a deny verdict blocks, an allow verdict allows.
func TestClientAppliesDenyAndAllow(t *testing.T) {
	var want execipc.Verdict
	srv := newStubServer(t, func(req execipc.Request) (execipc.Response, bool) {
		return execipc.Response{ID: req.ID, Verdict: want}, false
	})
	c := newTestClient(srv.socket)
	defer c.Close()

	want = execipc.VerdictDeny
	v, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 10, Path: "/bin/evil"})
	if err != nil || v != watchdog.VerdictBlock {
		t.Fatalf("deny verdict → (%v, %v), want (Block, nil)", v, err)
	}
	want = execipc.VerdictAllow
	v, err = c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 11, Path: "/bin/ok"})
	if err != nil || v != watchdog.VerdictAllow {
		t.Fatalf("allow verdict → (%v, %v), want (Allow, nil)", v, err)
	}
}

// TestMismatchedResponseIDIsRejected is the cross-talk test. Answering execution A with execution B's
// verdict is the worst available failure of an inline gate: silently wrong in BOTH directions and invisible
// in the audit trail. It must be an error, and the connection must be dropped — a desynchronized stream
// cannot be trusted to resynchronize itself.
//
// Mutation: accept a mismatched id → this FAILS.
func TestMismatchedResponseIDIsRejected(t *testing.T) {
	srv := newStubServer(t, func(req execipc.Request) (execipc.Response, bool) {
		return execipc.Response{ID: req.ID + 999, Verdict: execipc.VerdictDeny}, false
	})
	c := newTestClient(srv.socket)
	defer c.Close()

	v, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, Path: "/bin/x"})
	if !errors.Is(err, execipc.ErrIDMismatch) {
		t.Fatalf("err = %v, want ErrIDMismatch — a verdict for another exec must never be applied", err)
	}
	if v == watchdog.VerdictBlock {
		t.Fatal("a mismatched response produced a BLOCK — the gate applied another execution's verdict")
	}
}

// TestUnreachableSocketFailsOpen: no engine at all → an error (which the watchdog turns into an audited
// allow), never a block and never a hang.
func TestUnreachableSocketFailsOpen(t *testing.T) {
	c := newTestClient(filepath.Join(t.TempDir(), "nonexistent.sock"))
	defer c.Close()
	v, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, Path: "/bin/x"})
	if err == nil {
		t.Fatal("dialing a nonexistent socket returned no error")
	}
	if v != watchdog.VerdictAllow {
		t.Fatalf("verdict = %v, want Allow — a missing engine must never block an exec", v)
	}
}

// TestHungEngineFailsOpenWithinTimeout: the engine accepts and never answers. The client must return
// promptly with an error rather than waiting indefinitely.
func TestHungEngineFailsOpenWithinTimeout(t *testing.T) {
	srv := newStubServer(t, func(req execipc.Request) (execipc.Response, bool) {
		time.Sleep(5 * time.Second) // far beyond the client timeout
		return execipc.Response{ID: req.ID, Verdict: execipc.VerdictDeny}, false
	})
	c := newTestClient(srv.socket)
	defer c.Close()

	start := time.Now()
	v, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, Path: "/bin/slow"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a hung engine produced no error")
	}
	if v != watchdog.VerdictAllow {
		t.Fatalf("verdict = %v, want Allow", v)
	}
	if elapsed > time.Second {
		t.Fatalf("evaluate took %v — the client must give up on its own timeout, not wait on the peer", elapsed)
	}
}

// TestCircuitBreakerStopsCallingAfterConsecutiveFailures: with the engine dead, the gate must stop
// spending the permission budget on calls already known to fail.
//
// Mutation: remove the breaker → the socket keeps being dialed and callsAfter > 0 → this FAILS.
func TestCircuitBreakerStopsCallingAfterConsecutiveFailures(t *testing.T) {
	srv := newStubServer(t, func(req execipc.Request) (execipc.Response, bool) {
		return execipc.Response{}, true // close mid-exchange: every call fails
	})
	c := newTestClient(srv.socket)
	defer c.Close()

	const path = "/bin/storm"
	for i := 0; i < c.BreakerThreshold; i++ {
		if _, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: int32(i), Path: path}); err == nil {
			t.Fatalf("call %d unexpectedly succeeded", i)
		}
	}
	if c.BreakerTrips.Load() == 0 {
		t.Fatal("the breaker never tripped after the threshold was reached")
	}
	callsBefore := srv.calls.Load()

	// With the breaker open, further execs of this path fail open WITHOUT touching the socket.
	_, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 99, Path: path})
	if !errors.Is(err, execipc.ErrBreakerOpen) {
		t.Fatalf("err = %v, want ErrBreakerOpen", err)
	}
	if got := srv.calls.Load(); got != callsBefore {
		t.Errorf("the server saw %d more calls with the breaker open — it must not be dialed at all",
			got-callsBefore)
	}

	// After the cooldown it re-arms and tries again.
	time.Sleep(c.BreakerCooldown + 50*time.Millisecond)
	_, err = c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 100, Path: path})
	if errors.Is(err, execipc.ErrBreakerOpen) {
		t.Error("the breaker did not re-arm after its cooldown — a recovered engine would stay unused")
	}
}

// TestVerdictCacheCollapsesAForkStorm: a fork loop over one binary must not become an IPC storm.
func TestVerdictCacheCollapsesAForkStorm(t *testing.T) {
	srv := newStubServer(t, func(req execipc.Request) (execipc.Response, bool) {
		return execipc.Response{ID: req.ID, Verdict: execipc.VerdictAllow}, false
	})
	c := newTestClient(srv.socket)
	c.CacheTTL = 2 * time.Second
	defer c.Close()

	for i := 0; i < 50; i++ {
		if _, err := c.Evaluate(context.Background(),
			watchdog.PermissionEvent{PID: int32(i), Path: "/bin/forkbomb"}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := srv.calls.Load(); got != 1 {
		t.Errorf("50 execs of one path made %d pipeline calls, want 1 (the cache is the fork-storm defense)", got)
	}
	if c.CacheHits.Load() != 49 {
		t.Errorf("cache hits = %d, want 49", c.CacheHits.Load())
	}
}

// TestEngineRestartRecovers: an engine that dies and comes back must leave no stuck error state and no
// stuck denial — execs during the outage fail open, and the next exec after recovery is evaluated again.
func TestEngineRestartRecovers(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "restart.sock")
	answer := func(req execipc.Request) (execipc.Response, bool) {
		return execipc.Response{ID: req.ID, Verdict: execipc.VerdictDeny}, false
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	s1 := &stubServer{socket: socket, ln: ln, handle: answer}
	go s1.serve()

	c := newTestClient(socket)
	c.BreakerThreshold = 100 // keep the breaker out of this test's way
	defer c.Close()

	if v, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, Path: "/bin/a"}); err != nil || v != watchdog.VerdictBlock {
		t.Fatalf("before restart: (%v, %v), want (Block, nil)", v, err)
	}

	// The engine goes away, socket file and all.
	s1.stop()
	_ = os.Remove(socket)
	if _, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 2, Path: "/bin/b"}); err == nil {
		t.Fatal("an exec during the engine outage did not error (so it would not have been audited)")
	}

	// It comes back on the same socket.
	ln2, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	s2 := &stubServer{socket: socket, ln: ln2, handle: answer}
	go s2.serve()
	defer s2.stop()

	deadline := time.Now().Add(2 * time.Second)
	for {
		v, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 3, Path: "/bin/c"})
		if err == nil && v == watchdog.VerdictBlock {
			return // recovered: evaluating normally again
		}
		if time.Now().After(deadline) {
			t.Fatalf("the client never recovered after the engine restarted: (%v, %v)", v, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestInFlightOverflowFailsOpen: an unbounded queue in a privileged process under a fork storm is a
// memory-exhaustion bug, so overflow must fail open immediately.
func TestInFlightOverflowFailsOpen(t *testing.T) {
	release := make(chan struct{})
	srv := newStubServer(t, func(req execipc.Request) (execipc.Response, bool) {
		<-release // hold every request open
		return execipc.Response{ID: req.ID, Verdict: execipc.VerdictAllow}, false
	})
	c := newTestClient(srv.socket)
	c.Timeout = 3 * time.Second // long enough that the holder does not time out first
	c.MaxInFlight = 1
	defer c.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, Path: "/bin/hold"})
	}()
	time.Sleep(150 * time.Millisecond) // let the holder take the only slot

	_, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 2, Path: "/bin/other"})
	if !errors.Is(err, execipc.ErrOverflow) {
		t.Errorf("err = %v, want ErrOverflow", err)
	}
	close(release)
	wg.Wait()
}
