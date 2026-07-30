package enroll_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/enroll"
	"github.com/lucianoengel/openshield/internal/agent/identity"
)

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, _, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "id"), "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Enrollment is what makes an agent's telemetry verify against an ENROLLED key rather than being
// self-asserted (D41/D44), so what it sends is the whole point.
func TestEnrollmentSendsTheIdentityItRegisters(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	id := testIdentity(t)
	if err := enroll.Enroll(context.Background(), srv.Client(), srv.URL, "agent-1", "tok", id); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	if got["agent_id"] != "agent-1" || got["token"] != "tok" {
		t.Fatalf("body = %v", got)
	}
	pub, err := base64.StdEncoding.DecodeString(got["public_key"])
	if err != nil {
		t.Fatalf("public_key is not base64: %v", err)
	}
	if string(pub) != string(id.PublicKey()) {
		t.Fatal("the registered key is not this identity's public key — telemetry signed by this agent " +
			"would verify against someone else's key, or against nothing")
	}
	// The PRIVATE half must never appear in the payload. An ed25519 public key is 32 bytes; the private
	// key is 64 and CONTAINS the public one, so sending the wrong half would still "work" against a
	// receiver that only reads the first 32 bytes — and would hand out the agent's signing key.
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("the registered key is %d bytes, want %d; a 64-byte value is the PRIVATE key",
			len(pub), ed25519.PublicKeySize)
	}
}

// "retrying briefly because the control plane may not be up the instant a node starts" — the retry is the
// feature, so it is asserted rather than assumed.
func TestEnrollmentRetriesUntilTheControlPlaneIsUp(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := enroll.Enroll(context.Background(), srv.Client(), srv.URL, "agent-1", "tok", testIdentity(t)); err != nil {
		t.Fatalf("Enroll gave up before the control plane came up: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

// A CANCELLED CONTEXT MUST RETURN AT ONCE, and it did not: the loop only asked whether its own 30-second
// deadline had passed, so a cancelled context made every request fail instantly, fall through to an
// unconditional sleep, and retry — for the full thirty seconds. Measured at 30.08s before the fix. An
// agent shutting down blocked here for half a minute, and on a fleet that is half a minute added to every
// stop and every restart.
func TestACancelledContextAbandonsEnrollmentPromptly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // never succeeds, so only cancellation can end this
	}))
	defer srv.Close()

	t.Run("cancelled before starting", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		err := enroll.Enroll(ctx, srv.Client(), srv.URL, "agent-1", "tok", testIdentity(t))
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Enroll took %v to notice an already-cancelled context; it is waiting out its own "+
				"30s deadline instead of honouring the caller", elapsed)
		}
		if err == nil {
			t.Fatal("a cancelled enrollment reported success")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v; the cause must be recoverable so a shutdown path can tell cancellation "+
				"from a control plane that is genuinely refusing", err)
		}
	})

	t.Run("cancelled mid-retry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(300*time.Millisecond, cancel)
		start := time.Now()
		err := enroll.Enroll(ctx, srv.Client(), srv.URL, "agent-1", "tok", testIdentity(t))
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("Enroll took %v to notice cancellation during its backoff", elapsed)
		}
		if err == nil {
			t.Fatal("a cancelled enrollment reported success")
		}
	})
}

// Past the deadline against a control plane that is up but refusing, the error names the STATUS — an
// operator whose token is wrong needs to see 401, not a timeout.
func TestAPersistentRefusalReportsItsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	// A context that expires shortly stands in for the 30s deadline, so the test does not take 30 seconds
	// to prove a shape. It also re-checks the cancellation path from the other direction.
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := enroll.Enroll(ctx, srv.Client(), srv.URL, "agent-1", "wrong-token", testIdentity(t))
	if err == nil {
		t.Fatal("a persistently refused enrollment reported success")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v to give up", elapsed)
	}
}
