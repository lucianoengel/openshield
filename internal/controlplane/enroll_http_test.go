package controlplane_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func postEnroll(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func enrollBody(token, agentID string, pub []byte) string {
	b, _ := json.Marshal(map[string]string{
		"token": token, "agent_id": agentID, "public_key": base64.StdEncoding.EncodeToString(pub),
	})
	return string(b)
}

// A valid token enrolls over HTTP, the identity is recorded, and a signed message
// from that agent then verifies — enroll-over-HTTP feeds the D50 chain.
func TestEnrollOverHTTP(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	h := srv.EnrollHandler()
	ctx := context.Background()

	tok, err := srv.IssueToken(ctx, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Generate("agent-http")

	w := postEnroll(t, h, enrollBody(tok, "agent-http", id.PublicKey()))
	if w.Code != http.StatusOK {
		t.Fatalf("enroll status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	// The enrolled agent's signed telemetry now verifies.
	payload, err := proto.Marshal(&corev1.Event{EventId: "http-1", AgentId: "agent-http"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.VerifySigned(ctx, "agent-http", 1, payload, id.Sign(1, payload), time.Now()); err != nil {
		t.Fatalf("signed telemetry from the HTTP-enrolled agent did not verify: %v", err)
	}
}

// A spent/expired/unknown token → 401 generic (indistinguishable); malformed body
// → 400; wrong-size key → 400.
func TestEnrollErrors(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	h := srv.EnrollHandler()
	ctx := context.Background()
	id, _ := identity.Generate("agent-e")

	// Unknown token.
	unknown := postEnroll(t, h, enrollBody("deadbeef", "agent-e", id.PublicKey()))
	// Expired token.
	expTok, _ := srv.IssueToken(ctx, time.Millisecond, time.Now().Add(-time.Hour))
	expired := postEnroll(t, h, enrollBody(expTok, "agent-e", id.PublicKey()))
	// Used token.
	usedTok, _ := srv.IssueToken(ctx, time.Hour, time.Now())
	_ = postEnroll(t, h, enrollBody(usedTok, "agent-e", id.PublicKey())) // consume it
	used := postEnroll(t, h, enrollBody(usedTok, "agent-e2", id.PublicKey()))

	for name, w := range map[string]*httptest.ResponseRecorder{"unknown": unknown, "expired": expired, "used": used} {
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s token status = %d, want 401", name, w.Code)
		}
	}
	// The three refusals must be INDISTINGUISHABLE (same generic body).
	if unknown.Body.String() != expired.Body.String() || expired.Body.String() != used.Body.String() {
		t.Error("enrollment refusals differ between token states — that leaks token status to a prober")
	}

	// Malformed body → 400.
	if w := postEnroll(t, h, "{not json"); w.Code != http.StatusBadRequest {
		t.Errorf("malformed body status = %d, want 400", w.Code)
	}
	// Wrong-size public key → 400.
	tok, _ := srv.IssueToken(ctx, time.Hour, time.Now())
	body, _ := json.Marshal(map[string]string{"token": tok, "agent_id": "x", "public_key": base64.StdEncoding.EncodeToString([]byte("short"))})
	if w := postEnroll(t, h, string(body)); w.Code != http.StatusBadRequest {
		t.Errorf("wrong-size key status = %d, want 400", w.Code)
	}
}
