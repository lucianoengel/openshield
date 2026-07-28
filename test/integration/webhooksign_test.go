//go:build integration

package integration

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/notify"
)

// THE AUTHENTICATED WEBHOOK BODY (SIEM-8/8b), as a receiver actually sees it.
//
// A webhook URL is an unauthenticated open endpoint. Anyone who learns it can POST a fabricated incident
// into someone's paging system, and — worse for a security product — anyone who captures one delivery can
// replay it forever. `OPENSHIELD_ALERT_WEBHOOK_SECRET` is what lets the receiver tell a real alert from
// either.
//
// The scenarios below verify with the SHIPPED verifier (`notify.VerifySignature`) rather than
// re-implementing the scheme, because a test that recomputes the MAC its own way proves the two agree
// with each other and nothing about what a third-party receiver would accept.

// signedSink captures what a receiver needs to authenticate a delivery: the raw body and both headers.
// The body must be kept RAW — re-encoding parsed JSON changes the bytes and the MAC covers bytes.
type signedSink struct {
	mu   sync.Mutex
	body []byte
	ts   string
	sig  string
	n    int
	addr string
}

func startSignedSink(t *testing.T) *signedSink {
	t.Helper()
	s := &signedSink{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.body, s.ts, s.sig = b, r.Header.Get(notify.TimestampHeader), r.Header.Get(notify.SignatureHeader)
		s.n++
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

func (s *signedSink) delivery(t *testing.T) (body []byte, ts, sig string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.body, s.ts, s.sig
}

func (s *signedSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// deliverAnAlert raises a real incident and returns once the sink has a delivery.
func deliverAnAlert(t *testing.T, stack *Stack, subject string, extraEnv ...string) {
	t.Helper()
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	seedBurst(t, stack, subject, 5, 0.95)
	Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	}, extraEnv...))
}

// TestASignedAlertIsVerifiableAndSecretDependent.
//
// The second half is what makes this a test of the SECRET rather than of a header existing: the same
// delivery must FAIL verification under a different secret. A build that signed with a fixed key, or
// with an empty one, would satisfy "there is a signature header" and satisfy "it verifies under the key
// I configured" only if the key is genuinely the input.
func TestASignedAlertIsVerifiableAndSecretDependent(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	receiver := startSignedSink(t)

	const secret = "an-operator-chosen-webhook-secret"
	setDynamic(t, stack, "OPENSHIELD_ALERT_WEBHOOK", "http://"+receiver.addr+"/hook")
	deliverAnAlert(t, stack, "subject-signed-webhook", "OPENSHIELD_ALERT_WEBHOOK_SECRET="+secret)

	Eventually(t, 120*time.Second, "a signed alert to reach the receiver", func() bool {
		return receiver.count() > 0
	})
	body, ts, sig := receiver.delivery(t)

	if sig == "" {
		t.Fatal("the delivery carried no signature header, so a receiver cannot tell it from a POST by " +
			"anyone who learned the webhook URL")
	}
	if !notify.VerifySignature([]byte(secret), body, ts, sig, time.Now(), notify.ReplayTolerance) {
		t.Errorf("the delivery does NOT verify under the configured secret (ts=%q sig=%q, %d body bytes) "+
			"— a receiver following the documented scheme would reject every real alert", ts, sig, len(body))
	}
	if notify.VerifySignature([]byte("a-different-secret"), body, ts, sig, time.Now(), notify.ReplayTolerance) {
		t.Error("the delivery ALSO verifies under a different secret, so the signature does not depend on " +
			"the operator's key — it authenticates nothing")
	}
}

// TestACapturedDeliveryDoesNotReplay is the SIEM-8b claim, and it is the one a signature over the body
// alone would fail.
//
// Binding the timestamp INTO the signed payload is what bounds a capture's lifetime. Without it a
// captured (body, signature) pair is a valid alert forever, and an attacker who once saw one delivery can
// page an on-call team at will — with a message the receiver has cryptographic reason to trust.
//
// It is checked by moving the VERIFIER's clock rather than by waiting: the property is that the signature
// is bound to its timestamp, and a test that slept out a five-minute tolerance would be a five-minute
// test proving the same thing.
func TestACapturedDeliveryDoesNotReplay(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	receiver := startSignedSink(t)

	const secret = "an-operator-chosen-webhook-secret"
	setDynamic(t, stack, "OPENSHIELD_ALERT_WEBHOOK", "http://"+receiver.addr+"/hook")
	deliverAnAlert(t, stack, "subject-replayed-webhook", "OPENSHIELD_ALERT_WEBHOOK_SECRET="+secret)

	Eventually(t, 120*time.Second, "a signed alert to reach the receiver", func() bool {
		return receiver.count() > 0
	})
	body, ts, sig := receiver.delivery(t)

	// Fresh now, so the capture is valid — otherwise the replay assertion below could pass because the
	// signature was never valid in the first place.
	if !notify.VerifySignature([]byte(secret), body, ts, sig, time.Now(), notify.ReplayTolerance) {
		t.Fatalf("the captured delivery does not verify even when fresh (ts=%q) — the replay half of this "+
			"scenario would prove nothing", ts)
	}

	// 1. THE ATTACKER'S ACTUAL MOVE: replay the captured body and signature with a FRESH timestamp.
	//
	// This is the assertion that tests the BINDING. An earlier version only aged the verifier's clock
	// past the tolerance — and a mutation that signed the body ALONE, leaving the timestamp unbound,
	// still passed it: `VerifySignature` rejects a stale timestamp on the window check BEFORE it ever
	// computes the MAC. The test asserted the right outcome through a path that did not depend on the
	// mechanism it claimed to cover. Forging the timestamp is what forces the MAC to be consulted.
	//
	// The forged value is derived from the CAPTURED one, not from time.Now(): within the same second
	// those are equal, the "forgery" is a no-op, verification correctly succeeds and the assertion fires
	// on correct code. This test passed once and failed the next run for exactly that reason — a second
	// boundary, not a behaviour change. Deriving it guarantees the value actually differs, and the check
	// below refuses to run if it somehow does not.
	captured, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		t.Fatalf("the delivery's timestamp header %q is not an integer: %v", ts, err)
	}
	forged := strconv.FormatInt(captured+1, 10) // one second on, still well inside the tolerance
	if forged == ts {
		t.Fatalf("the forged timestamp %q is identical to the captured one — this scenario would be "+
			"asserting nothing", forged)
	}
	if notify.VerifySignature([]byte(secret), body, forged, sig, time.Now(), notify.ReplayTolerance) {
		t.Error("a captured delivery verifies again once its TIMESTAMP HEADER is refreshed. The MAC does " +
			"not cover the timestamp, so the freshness window is decoration: anyone who captures one " +
			"alert can page an on-call team indefinitely with a message the receiver has cryptographic " +
			"reason to trust")
	}

	// 2. And the window check itself: an un-forged capture ages out.
	replayed := time.Now().Add(notify.ReplayTolerance + time.Minute)
	if notify.VerifySignature([]byte(secret), body, ts, sig, replayed, notify.ReplayTolerance) {
		t.Error("a delivery captured now still verifies well outside the replay tolerance")
	}
}

// TestAnUnsignedDeploymentSendsNoSignature.
//
// "Unset means unsigned" has to mean ABSENT, not signed with an empty key. A header computed under a
// zero-length secret is worse than none: it looks authenticated, and every deployment that forgot to set
// a secret produces the same one, so any of them can forge for any other.
func TestAnUnsignedDeploymentSendsNoSignature(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	receiver := startSignedSink(t)

	setDynamic(t, stack, "OPENSHIELD_ALERT_WEBHOOK", "http://"+receiver.addr+"/hook")
	deliverAnAlert(t, stack, "subject-unsigned-webhook") // no secret configured

	Eventually(t, 120*time.Second, "an alert to reach the receiver", func() bool {
		return receiver.count() > 0
	})
	_, _, sig := receiver.delivery(t)
	if sig != "" {
		t.Errorf("an unconfigured deployment still sent %s=%q. A signature under an empty secret is "+
			"identical across every such deployment, so it looks authenticated while authenticating "+
			"nothing", notify.SignatureHeader, sig)
	}
}
