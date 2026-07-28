package openipc

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// stubDecider answers with a fixed action or error.
type stubDecider struct {
	action corev1.Action
	err    error
	seen   chan string
}

func (d *stubDecider) DecideBytes(_ context.Context, path string, prefix []byte) (*corev1.Decision, error) {
	if d.seen != nil {
		d.seen <- string(prefix)
	}
	if d.err != nil {
		return nil, d.err
	}
	return &corev1.Decision{Action: d.action}, nil
}

// serve starts a server on a temp socket and returns its path.
func serve(t *testing.T, d Decider) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "open.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &Server{Decide: d, Timeout: time.Second}
	go func() { _ = srv.Listen(ctx, sock) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c := &Client{SocketPath: sock, Timeout: 200 * time.Millisecond}
		if _, err := c.dial(); err == nil {
			c.Close()
			return sock
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the server never became connectable")
	return ""
}

// TestTheServerRefusesWithoutADecider.
//
// A server that answered without deciding would be a gate reporting itself active while allowing
// everything — the failure shape this project treats as the most dangerous.
func TestTheServerRefusesWithoutADecider(t *testing.T) {
	err := (&Server{}).Listen(context.Background(), filepath.Join(t.TempDir(), "x.sock"))
	if err == nil {
		t.Fatal("a server with no decider started")
	}
}

// TestABlockingDecisionBecomesADeny, and the PREFIX ARRIVES — the bytes the agent read are what the
// decision is made from, so a server that decided on the path alone would pass a verdict test while
// ignoring content entirely.
func TestABlockingDecisionBecomesADeny(t *testing.T) {
	seen := make(chan string, 1)
	sock := serve(t, &stubDecider{action: corev1.Action_ACTION_BLOCK, seen: seen})

	c := &Client{SocketPath: sock, Timeout: time.Second}
	defer c.Close()
	resp, err := c.roundTrip(context.Background(), Request{ID: 1, PID: 5, Path: "/x", Prefix: []byte("cpf 111")})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != VerdictDeny {
		t.Errorf("a BLOCK decision produced %v, want VerdictDeny", resp.Verdict)
	}
	select {
	case got := <-seen:
		if got != "cpf 111" {
			t.Errorf("the decider saw prefix %q, want the bytes the agent read", got)
		}
	case <-time.After(time.Second):
		t.Error("the decider never received the prefix")
	}
}

// TestANonBlockingActionAllows: the mapping is explicit, so a new action added to the closed set does
// not silently become a reason to refuse an open.
func TestANonBlockingActionAllows(t *testing.T) {
	for _, a := range []corev1.Action{
		corev1.Action_ACTION_ALLOW,
		corev1.Action_ACTION_ALERT,
		corev1.Action_ACTION_UNSPECIFIED,
	} {
		sock := serve(t, &stubDecider{action: a})
		c := &Client{SocketPath: sock, Timeout: time.Second}
		resp, err := c.roundTrip(context.Background(), Request{ID: 1, Path: "/x"})
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.Verdict != VerdictAllow {
			t.Errorf("%v produced %v — only an action that MEANS refuse may deny an open", a, resp.Verdict)
		}
	}
}

// TestADecidingErrorAllows — the server allows explicitly rather than leaving the client to time out,
// which is faster and leaves the reason where it can be read.
func TestADecidingErrorAllows(t *testing.T) {
	sock := serve(t, &stubDecider{err: errors.New("worker unreachable")})
	c := &Client{SocketPath: sock, Timeout: time.Second}
	defer c.Close()
	resp, err := c.roundTrip(context.Background(), Request{ID: 1, Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != VerdictAllow {
		t.Errorf("a failed decision produced %v, want Allow — a file-open gate that refuses on its own "+
			"errors hangs processes for reasons unrelated to their content", resp.Verdict)
	}
}

// TestAStaleSocketIsReplaced: an engine restarting into a path its predecessor left behind is ordinary,
// and refusing there would leave the gate down after every unclean shutdown — with the agent failing
// open on every event, which is the state this exists to avoid.
func TestAStaleSocketIsReplaced(t *testing.T) {
	sock := serve(t, &stubDecider{action: corev1.Action_ACTION_ALLOW})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{Decide: &stubDecider{action: corev1.Action_ACTION_BLOCK}, Timeout: time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Listen(ctx, sock) }()
	select {
	case err := <-errCh:
		t.Fatalf("binding over a stale socket failed: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
}
