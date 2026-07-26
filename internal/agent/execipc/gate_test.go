package execipc_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/execipc"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// recordingResponder captures what the watchdog told the kernel.
type recordingResponder struct {
	mu      sync.Mutex
	allowed int
	denied  int
}

func (r *recordingResponder) Allow(watchdog.PermissionEvent) error {
	r.mu.Lock()
	r.allowed++
	r.mu.Unlock()
	return nil
}

func (r *recordingResponder) Deny(watchdog.PermissionEvent) error {
	r.mu.Lock()
	r.denied++
	r.mu.Unlock()
	return nil
}

func (r *recordingResponder) counts() (allowed, denied int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.allowed, r.denied
}

type auditRecord struct {
	severity watchdog.Severity
	reason   string
}

// gate builds the REAL watchdog around the IPC client — not a mock of it. The fail-open properties belong
// to watchdog.Handle, so testing them against a stand-in would prove nothing about the shipped path.
func gate(t *testing.T, c *execipc.Client, budget time.Duration) (*watchdog.Watchdog, *recordingResponder, *[]auditRecord, *sync.Mutex) {
	t.Helper()
	resp := &recordingResponder{}
	var mu sync.Mutex
	audits := []auditRecord{}
	w := &watchdog.Watchdog{
		SelfPID:   -1,
		Budget:    budget,
		Responder: resp,
		Evaluator: c,
		Audit: func(_ context.Context, _ watchdog.PermissionEvent, sev watchdog.Severity, reason string) error {
			mu.Lock()
			audits = append(audits, auditRecord{sev, reason})
			mu.Unlock()
			return nil
		},
	}
	return w, resp, &audits, &mu
}

// TestGateFailsOpenLoudlyWhenTheEngineIsGone is the load-bearing SAFETY test: with no engine, a real exec
// must be ALLOWED and the fail-open must be audited at high severity.
//
// MUTATION: change the gate to fail CLOSED on IPC failure → this test FAILS. That is the point. A
// privileged gate that fails closed when its evaluator dies removes the host's ability to run programs
// (D17/D73), so "fails open" here is a property to protect, not a bug to fix.
func TestGateFailsOpenLoudlyWhenTheEngineIsGone(t *testing.T) {
	c := newTestClient(t.TempDir() + "/absent.sock")
	defer c.Close()
	w, resp, audits, mu := gate(t, c, 500*time.Millisecond)

	if err := w.Handle(context.Background(), watchdog.PermissionEvent{PID: 4242, Path: "/bin/anything"}); err != nil {
		t.Fatalf("Handle returned %v — the kernel must still be answered", err)
	}
	allowed, denied := resp.counts()
	if denied != 0 {
		t.Fatalf("a dead engine DENIED an exec (%d denies) — a privileged gate must never brick execution", denied)
	}
	if allowed != 1 {
		t.Fatalf("allowed = %d, want 1", allowed)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*audits) != 1 {
		t.Fatalf("fail-open produced %d audit records, want 1 — a silent fail-open is the bypass", len(*audits))
	}
	if (*audits)[0].severity != watchdog.SeverityHigh {
		t.Errorf("fail-open audited at severity %v, want high", (*audits)[0].severity)
	}
	if !strings.Contains((*audits)[0].reason, "fail-open") {
		t.Errorf("audit reason %q does not name the fail-open", (*audits)[0].reason)
	}
}

// TestGateFailsOpenWhenTheEngineHangs: the same property when the engine accepts and never answers. The
// exec must be allowed within the budget rather than parked in the permission window.
func TestGateFailsOpenWhenTheEngineHangs(t *testing.T) {
	srv := newStubServer(t, func(req execipc.Request) (execipc.Response, bool) {
		time.Sleep(5 * time.Second)
		return execipc.Response{ID: req.ID, Verdict: execipc.VerdictDeny}, false
	})
	c := newTestClient(srv.socket)
	c.Timeout = 100 * time.Millisecond
	defer c.Close()
	w, resp, audits, mu := gate(t, c, 400*time.Millisecond)

	start := time.Now()
	if err := w.Handle(context.Background(), watchdog.PermissionEvent{PID: 5, Path: "/bin/slow"}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the exec was parked for %v — a hung engine must not hold the permission window", elapsed)
	}
	allowed, denied := resp.counts()
	if denied != 0 || allowed != 1 {
		t.Fatalf("hung engine → allowed=%d denied=%d, want allowed=1 denied=0", allowed, denied)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*audits) == 0 {
		t.Error("a hung engine's fail-open was not audited")
	}
}

// TestGateBlocksOnAPolicyDeny: the gate does its job when the engine answers deny — otherwise "fails open
// safely" would be indistinguishable from "never blocks anything".
func TestGateBlocksOnAPolicyDeny(t *testing.T) {
	srv := newStubServer(t, func(req execipc.Request) (execipc.Response, bool) {
		return execipc.Response{ID: req.ID, Verdict: execipc.VerdictDeny}, false
	})
	c := newTestClient(srv.socket)
	defer c.Close()
	w, resp, audits, mu := gate(t, c, 500*time.Millisecond)

	if err := w.Handle(context.Background(), watchdog.PermissionEvent{PID: 6, Path: "/bin/evil"}); err != nil {
		t.Fatal(err)
	}
	allowed, denied := resp.counts()
	if denied != 1 || allowed != 0 {
		t.Fatalf("policy deny → allowed=%d denied=%d, want allowed=0 denied=1", allowed, denied)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*audits) != 0 {
		t.Errorf("a clean deny produced %d fail-open audits, want 0", len(*audits))
	}
}

// TestGateCrossTalkNeverBlocks: an id-mismatched answer must not become a block. Through the real watchdog
// this is the difference between "audited fail-open" and "a random program refused for no recorded reason".
func TestGateCrossTalkNeverBlocks(t *testing.T) {
	srv := newStubServer(t, func(req execipc.Request) (execipc.Response, bool) {
		return execipc.Response{ID: req.ID ^ 0xFFFF, Verdict: execipc.VerdictDeny}, false
	})
	c := newTestClient(srv.socket)
	defer c.Close()
	w, resp, _, _ := gate(t, c, 500*time.Millisecond)

	if err := w.Handle(context.Background(), watchdog.PermissionEvent{PID: 7, Path: "/bin/x"}); err != nil {
		t.Fatal(err)
	}
	if _, denied := resp.counts(); denied != 0 {
		t.Fatal("a mismatched verdict became a kernel DENY — the gate applied another exec's answer")
	}
}

// TestServerAnswersFromTheEvaluator drives the real Server against the real Client over a real socket, with
// the server's verdict coming from an injected evaluator (production injects the execguard-backed one).
func TestServerAnswersFromTheEvaluator(t *testing.T) {
	for _, tc := range []struct {
		name    string
		verdict watchdog.Verdict
		err     error
		want    watchdog.Verdict
		wantErr bool
	}{
		{name: "deny", verdict: watchdog.VerdictBlock, want: watchdog.VerdictBlock},
		{name: "allow", verdict: watchdog.VerdictAllow, want: watchdog.VerdictAllow},
		// A pipeline error must NOT be laundered into a permissive verdict: the server drops the
		// connection, the client sees a read error, and the watchdog fails open with an audit. If the
		// server answered "allow" here, an evaluation failure would be indistinguishable from a decision.
		{name: "evaluation error", err: errors.New("policy exploded"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := t.TempDir() + "/verdict.sock"
			srv := &execipc.Server{
				Evaluate: func(context.Context, watchdog.PermissionEvent) (watchdog.Verdict, error) {
					return tc.verdict, tc.err
				},
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = srv.Listen(ctx, socket) }()
			waitForSocket(t, socket)

			c := newTestClient(socket)
			defer c.Close()
			got, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, Path: "/bin/t"})
			if tc.wantErr {
				if err == nil {
					t.Fatal("an evaluation error produced no client error — it was laundered into a verdict")
				}
				if got == watchdog.VerdictBlock {
					t.Fatal("an evaluation error produced a BLOCK")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("verdict = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestServerRemovesStaleSocket: an unclean shutdown leaves a socket file behind. If bind failed on it, the
// engine would come back with the exec gate silently unable to get verdicts for the life of the process.
func TestServerRemovesStaleSocket(t *testing.T) {
	socket := t.TempDir() + "/stale.sock"
	for i := 0; i < 2; i++ {
		srv := &execipc.Server{
			Evaluate: func(context.Context, watchdog.PermissionEvent) (watchdog.Verdict, error) {
				return watchdog.VerdictAllow, nil
			},
		}
		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- srv.Listen(ctx, socket) }()
		waitForSocket(t, socket)
		cancel()
		if err := <-errCh; err != nil {
			t.Fatalf("listen pass %d: %v", i, err)
		}
		// The socket file survives the shutdown; the next pass must bind over it.
	}
}

func waitForSocket(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c := execipc.NewClient(socket)
		c.Timeout = 100 * time.Millisecond
		_, err := c.Evaluate(context.Background(), watchdog.PermissionEvent{PID: 1, Path: "/probe"})
		_ = c.Close()
		if err == nil || !strings.Contains(err.Error(), "dial") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s never became reachable", socket)
}
