//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// RESPONSE INTENTS, published for real (D291, SOAR-7 Tier-2).
//
// The consumer side of this was already wired and running: the IdP responder verifies an intent's
// signature and disables an account. The PRODUCER side had no caller anywhere in the product, so the
// responder was listening on a subject nothing could publish to — a verifier with no possible signer,
// which reads as a working control and is an inert one.
//
// These scenarios drive the two-step operator flow end to end and assert on what actually crosses the
// broker, because the signature and the closed vocabulary are properties OF THE WIRE, and a test that
// stopped at the HTTP response would not see either.

// intentSubscriber returns a channel of the intents published on the broker.
//
// It subscribes BEFORE the publication, which is the only ordering that proves delivery: NATS core is
// at-most-once and fire-and-forget, so a subscriber attached afterwards sees nothing and a test built
// that way would pass whether or not anything was ever sent.
func intentSubscriber(t *testing.T, natsURL string, m TLSMaterial) <-chan *corev1.ResponseIntent {
	t.Helper()
	conn, err := nats.Connect(natsURL, nats.ClientCert(m.Cert, m.Key), nats.RootCAs(m.CA))
	if err != nil {
		t.Fatalf("connecting to the stack broker: %v", err)
	}
	t.Cleanup(conn.Close)
	ch := make(chan *corev1.ResponseIntent, 16)
	sub, err := conn.Subscribe(natsx.SubjectIntent, func(m *nats.Msg) {
		var signed corev1.SignedUpdate
		if err := proto.Unmarshal(m.Data, &signed); err != nil {
			return
		}
		var intent corev1.ResponseIntent
		if err := proto.Unmarshal(signed.GetPayload(), &intent); err != nil {
			return
		}
		// The SIGNATURE is carried through so the test can assert it is present and non-empty. Verifying
		// it against the control plane's key is the responder's job and has its own tests; what matters
		// here is that the published message is signed at all.
		if len(signed.GetSignature()) == 0 {
			t.Error("an intent was published with NO SIGNATURE — an unsigned intent creates a window in " +
				"which a forging publisher is indistinguishable from the control plane, and containment " +
				"is a far more attractive forgery target than a risk score")
		}
		ch <- &intent
	})
	if err != nil {
		t.Fatalf("subscribing to intents: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return ch
}

// TestAHighImpactIntentNeedsTwoOperatorsAndThenReachesTheBroker is the whole Tier-2 flow.
func TestAHighImpactIntentNeedsTwoOperatorsAndThenReachesTheBroker(t *testing.T) {
	p := newPKI(t)
	stack, srv, base := mtlsServerSigned(t, p)
	intents := intentSubscriber(t, stack.NATSURL, p.tls)

	alice := p.operator(t, "responder", "alice")
	bob := p.operator(t, "responder", "bob")

	// Step 1: prepare. Nothing is published, and a four-eyes request is opened.
	q := url.Values{"verb": {"contain"}, "subject": {"subject-contain-1"}, "reason": {"exfil to a personal drive"}}
	code, body := do(t, alice, http.MethodPost, base+"/intents/prepare?"+q.Encode(), nil)
	if code != http.StatusOK {
		t.Fatalf("preparing an intent: %d %s\n%s", code, body, srv.Output())
	}
	var prep struct {
		IntentIDs   []string `json:"intent_ids"`
		ApprovalIDs []int64  `json:"approval_ids"`
		HighImpact  bool     `json:"high_impact"`
	}
	if err := json.Unmarshal([]byte(body), &prep); err != nil {
		t.Fatalf("parsing %q: %v", body, err)
	}
	if !prep.HighImpact || len(prep.ApprovalIDs) != 1 {
		t.Fatalf("CONTAIN was not treated as high-impact: %s", body)
	}
	select {
	case got := <-intents:
		t.Fatalf("preparing an intent PUBLISHED it (%s) — the four-eyes gate is checked before anything "+
			"is signed or sent precisely so an unapproved containment never exists on the wire, where a "+
			"consumer that received it would already have acted", got.GetIntentId())
	case <-time.After(2 * time.Second):
	}

	// Publishing without the approval is refused.
	pub := base + "/intents/publish?id=" + url.QueryEscape(prep.IntentIDs[0]) + "&reason=exfil&ttl=1h"
	if code, body = do(t, alice, http.MethodPost, pub, nil); code != http.StatusForbidden {
		t.Fatalf("an UNAPPROVED containment published: %d %s\n%s", code, body, srv.Output())
	}

	// Alice cannot approve her own request; Bob can.
	res := fmt.Sprintf("%s/approvals/resolve?id=%d&approve=true", base, prep.ApprovalIDs[0])
	if code, body = do(t, alice, http.MethodPost, res, nil); code != http.StatusForbidden {
		t.Fatalf("Alice approved HER OWN containment request: %d %s", code, body)
	}
	if code, body = do(t, bob, http.MethodPost, res, nil); code != http.StatusOK {
		t.Fatalf("Bob could not approve: %d %s\n%s", code, body, srv.Output())
	}

	// Step 2: publish. THE APPROVED ID, not a freshly computed one — which is the bug this flow exists
	// to avoid, since the id carries the minute it was issued in.
	if code, body = do(t, alice, http.MethodPost, pub, nil); code != http.StatusOK {
		t.Fatalf("an APPROVED containment was refused: %d %s\n%s", code, body, srv.Output())
	}

	select {
	case got := <-intents:
		if got.GetVerb() != corev1.IntentVerb_INTENT_VERB_CONTAIN {
			t.Errorf("the published verb is %v, want CONTAIN", got.GetVerb())
		}
		if got.GetSubject() != "subject-contain-1" {
			t.Errorf("the intent targets %q", got.GetSubject())
		}
		if got.GetIntentId() != prep.IntentIDs[0] {
			t.Errorf("published intent id %q, want the APPROVED %q — an approval authorizes one intent, "+
				"and publishing a different id means the approval authorized nothing that was sent",
				got.GetIntentId(), prep.IntentIDs[0])
		}
		// A contain with no expiry is a permanent quarantine nobody remembers issuing.
		if got.GetExpiresAt() == nil || !got.GetExpiresAt().AsTime().After(got.GetIssuedAt().AsTime()) {
			t.Error("the intent carries no future expiry")
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("nothing reached the broker after an approved publication\n%s", srv.Output())
	}
}

// TestTheBlastRadiusCeilingIsInstalled covers the setting that was declared, checked, and never set.
//
// `SetIntentBlastRadius` had no caller, so the ceiling the check compared against was always zero — which
// the code reads as "no ceiling". The check ran on every publication and could never refuse anything.
func TestTheBlastRadiusCeilingIsInstalled(t *testing.T) {
	p := newPKI(t)
	stack, srv, base := mtlsServerSigned(t, p)
	setDynamic(t, stack, "OPENSHIELD_INTENT_BLAST_RADIUS", "2")
	rita := p.operator(t, "responder", "rita")

	// ELEVATE_SCRUTINY is low-impact, which isolates the ceiling from the four-eyes gate — otherwise a
	// refusal could be either control and the test would not know which it had proven.
	prepare := func(subjects ...string) []string {
		t.Helper()
		q := url.Values{"verb": {"elevate-scrutiny"}, "reason": {"testing the ceiling"}}
		for _, s := range subjects {
			q.Add("subject", s)
		}
		code, body := do(t, rita, http.MethodPost, base+"/intents/prepare?"+q.Encode(), nil)
		if code != http.StatusOK {
			t.Fatalf("preparing: %d %s", code, body)
		}
		var prep struct {
			IntentIDs  []string `json:"intent_ids"`
			HighImpact bool     `json:"high_impact"`
		}
		if err := json.Unmarshal([]byte(body), &prep); err != nil {
			t.Fatal(err)
		}
		if prep.HighImpact {
			t.Fatalf("ELEVATE_SCRUTINY was treated as high-impact: %s", body)
		}
		return prep.IntentIDs
	}
	publish := func(ids []string) (int, string) {
		t.Helper()
		q := url.Values{"reason": {"x"}}
		for _, id := range ids {
			q.Add("id", id)
		}
		return do(t, rita, http.MethodPost, base+"/intents/publish?"+q.Encode(), nil)
	}

	// AT the ceiling publishes. Wait for the value to be applied first — it is read from the store on a
	// timer, so asserting immediately would be asserting against whatever the process last read.
	Eventually(t, 60*time.Second, "the configured ceiling to be applied", func() bool {
		code, _ := publish(prepare("a", "b", "c"))
		return code == http.StatusForbidden
	})
	if code, body := publish(prepare("a", "b")); code != http.StatusOK {
		t.Fatalf("a publication AT the ceiling of 2 was refused: %d %s\n%s", code, body, srv.Output())
	}

	// OVER it is refused AS A WHOLE. The blast radius is checked before any approval lookup or
	// publication precisely so an over-broad request is not partially enacted across the first N
	// subjects — a half-contained fleet is the worst of both outcomes.
	intents := intentSubscriber(t, stack.NATSURL, p.tls)
	code, body := publish(prepare("x", "y", "z"))
	if code != http.StatusForbidden {
		t.Fatalf("a publication OVER the ceiling was allowed: %d %s\n%s", code, body, srv.Output())
	}
	select {
	case got := <-intents:
		t.Errorf("an over-broad publication still put %q on the wire — the ceiling must refuse the whole "+
			"request, because a consumer that received one of these has already acted on it",
			got.GetIntentId())
	case <-time.After(3 * time.Second):
	}
}

// TestAnApprovedIntentSurvivesTheMinuteBoundary is the test that proves the id pinning matters.
//
// It exists because the obvious mutation — publish computing a FRESH id from the clock instead of the
// approved one — PASSED the flow test above. That test prepares and publishes within a second, so both
// ids fall in the same minute and the two behaviours are indistinguishable. A mutation that does not
// fail means the test does not cover the property, whatever the property's comment says.
//
// So this one deliberately straddles the boundary: it waits until a minute is nearly over, prepares and
// approves, then publishes after the minute has rolled. Without pinning, the publication computes an id
// for the NEW minute, finds no approval bound to it, and refuses — while an approval sits there
// approved, which is exactly what an operator would hit in production roughly once every sixty attempts.
//
// The cost is a wait of up to a minute, once. That is the honest price of testing a minute-granularity
// race, and it is cheaper than the bug.
func TestAnApprovedIntentSurvivesTheMinuteBoundary(t *testing.T) {
	p := newPKI(t)
	_, srv, base := mtlsServerSigned(t, p)
	alice := p.operator(t, "responder", "alice")
	bob := p.operator(t, "responder", "bob")

	// Wait until the current minute is nearly spent, so prepare and publish land on opposite sides.
	for time.Now().Second() < 55 {
		time.Sleep(500 * time.Millisecond)
	}

	q := url.Values{"verb": {"contain"}, "subject": {"subject-boundary"}, "reason": {"minute boundary"}}
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
	res := fmt.Sprintf("%s/approvals/resolve?id=%d&approve=true", base, prep.ApprovalIDs[0])
	if code, body = do(t, bob, http.MethodPost, res, nil); code != http.StatusOK {
		t.Fatalf("approving: %d %s", code, body)
	}

	// Cross the boundary.
	for time.Now().Second() >= 55 {
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)

	pub := base + "/intents/publish?id=" + url.QueryEscape(prep.IntentIDs[0]) + "&reason=boundary"
	if code, body = do(t, alice, http.MethodPost, pub, nil); code != http.StatusOK {
		t.Fatalf("an APPROVED intent was refused after the minute rolled over (%d %s). The approval is "+
			"bound to an id derived from the issuing MINUTE, so a publication that recomputes the id from "+
			"the current clock looks up an approval that was never requested — and the high-impact path "+
			"becomes a coin flip on where in the minute the operator happened to be\n%s",
			code, body, srv.Output())
	}
}
