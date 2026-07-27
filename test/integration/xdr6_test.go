//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

// COORDINATED RESPONSE (XDR-6), end to end: ONE approved containment, consumed by BOTH enforcement
// components (D294).
//
// The premise of XDR-6 is that a single approved CONTAIN is enacted by the gateway on flows and by the
// endpoint on execs, each stamping the same intent id so both enactments are traceable to one decision.
// Before this, NEITHER HALF LISTENED: `Gateway.intents` was an unexported field read on every request and
// assigned by nothing — no setter existed to install one — and `Engine.SetIntentResolver` had no caller.
//
// So D291's work published a signed, four-eyes-gated containment to a subject nothing that enforces
// subscribed to. The producer and both consumers each had passing tests.
//
// This scenario asserts the seam that nothing else can: that a running gateway and a running endpoint,
// given the control plane's key, both come up consuming the channel.

// TestBothEnforcementComponentsConsumeCoordinatedIntents drives a real containment onto the wire and
// asserts both components are subscribed to receive it.
func TestBothEnforcementComponentsConsumeCoordinatedIntents(t *testing.T) {
	p := newPKI(t)
	stack, srv, base := mtlsServerSigned(t, p)

	// The control-plane PUBLIC key, which is what a consumer verifies against. It is the public half of
	// the same key the server signs with — a consumer holding anything else would reject every intent,
	// which from outside is indistinguishable from a quiet channel.
	pub := p.controlPlanePub(t)

	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSNFor(t, "gwintents"),
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_CONTROL_PLANE_KEY=" + pub,
		"OPENSHIELD_BREAK_GLASS=" + filepath.Join(t.TempDir(), "EMERGENCY_DISABLE"),
		"OPENSHIELD_TLS_CA=" + p.tls.CA,
		"OPENSHIELD_TLS_CERT=" + p.tls.Cert,
		"OPENSHIELD_TLS_KEY=" + p.tls.Key,
	})
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSNFor(t, "engintents"),
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_CONTROL_PLANE_KEY=" + pub,
		"OPENSHIELD_BREAK_GLASS=" + filepath.Join(t.TempDir(), "EMERGENCY_DISABLE"),
		"OPENSHIELD_TLS_CA=" + p.tls.CA,
		"OPENSHIELD_TLS_CERT=" + p.tls.Cert,
		"OPENSHIELD_TLS_KEY=" + p.tls.Key,
	})

	// Both come up on the channel. This is a STARTUP signal only — deliberately not the assertion, for a
	// reason the mutation round taught: removing the subscription while leaving the log line in place
	// made an earlier version of this test pass. A component can announce that it consumes intents
	// while consuming none. The assertion is further down, on an intent actually being APPLIED.
	gw.WaitForOutput("coordinated-response intents ACTIVE", 90*time.Second)
	eng.WaitForOutput("coordinated-response intents ACTIVE", 90*time.Second)

	// And a real containment goes out on the channel they are listening to.
	alice := p.operator(t, "responder", "alice")
	bob := p.operator(t, "responder", "bob")
	q := url.Values{"verb": {"contain"}, "subject": {"subject-xdr6"}, "reason": {"coordinated response"}}
	code, body := do(t, alice, http.MethodPost, base+"/intents/prepare?"+q.Encode(), nil)
	if code != http.StatusOK {
		t.Fatalf("preparing: %d %s", code, body)
	}
	var prep struct {
		IntentIDs   []string `json:"intent_ids"`
		ApprovalIDs []int64  `json:"approval_ids"`
	}
	if err := json.Unmarshal([]byte(body), &prep); err != nil {
		t.Fatal(err)
	}
	if code, body = do(t, bob, http.MethodPost,
		base+"/approvals/resolve?id="+itoaTest(prep.ApprovalIDs[0])+"&approve=true", nil); code != http.StatusOK {
		t.Fatalf("approving: %d %s", code, body)
	}
	if code, body = do(t, alice, http.MethodPost,
		base+"/intents/publish?id="+url.QueryEscape(prep.IntentIDs[0])+"&reason=coordinated", nil); code != http.StatusOK {
		t.Fatalf("publishing: %d %s\n%s", code, body, srv.Output())
	}

	// THE ASSERTION: both components APPLIED the intent, and both name the SAME intent id. One approved
	// containment, two enactments, one id — that is the whole content of XDR-6, and it is the thing a
	// startup log line cannot tell you.
	gw.WaitForOutput("coordinated-response intent APPLIED", 60*time.Second)
	eng.WaitForOutput("coordinated-response intent APPLIED", 60*time.Second)
	for name, out := range map[string]string{"gateway": gw.Output(), "engine": eng.Output()} {
		if !contains(out, prep.IntentIDs[0]) {
			t.Errorf("the %s applied an intent but not %q — both enactments must be traceable to ONE "+
				"approved decision, which is what the shared intent id is for\n%s",
				name, prep.IntentIDs[0], out)
		}
		if !contains(out, "subject-xdr6") {
			t.Errorf("the %s did not name the contained subject\n%s", name, out)
		}
	}

	// Neither component may have DIED on receiving it. A consumer that crashes on a verified message is
	// worse than one that ignores it: the containment takes the enforcement component down with it.
	time.Sleep(3 * time.Second)
	if gw.Cmd.ProcessState != nil {
		t.Errorf("the gateway exited after receiving a containment\n%s", gw.Output())
	}
	if eng.Cmd.ProcessState != nil {
		t.Errorf("the engine exited after receiving a containment\n%s", eng.Output())
	}
}

func itoaTest(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
