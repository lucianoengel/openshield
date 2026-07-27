//go:build integration

package integration

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// THE IdP RESPONDER (D309) — the far end of the response chain.
//
// D291 gave the control plane a way to PUBLISH a signed, four-eyes-gated REVOKE_TRUST. D294 gave the
// gateway and endpoint a way to consume intents. This is the third consumer and the only one that acts
// OUTSIDE the platform: it calls someone else's identity provider and disables an account.
//
// It is also the consumer with the sharpest failure mode, stated in the product's own startup notice:
// **these actions are NOT undone by intent expiry.** Every other enactment here is restored when the TTL
// lapses; a disabled account stays disabled. So the gate on it — a verified signature against the
// control plane's key — is the only thing between a forged message and somebody losing their access.

type idpServer struct {
	mu     sync.Mutex
	calls  []map[string]any
	auth   string
	addr   string
	status int
}

func startIdP(t *testing.T) *idpServer {
	t.Helper()
	s := &idpServer{status: http.StatusOK}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		s.mu.Lock()
		s.calls = append(s.calls, m)
		s.auth = r.Header.Get("Authorization")
		st := s.status
		s.mu.Unlock()
		w.WriteHeader(st)
		_, _ = w.Write([]byte(`{}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

func (s *idpServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *idpServer) actions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.calls))
	for _, c := range s.calls {
		a, _ := c["action"].(string)
		out = append(out, a)
	}
	return out
}

// TestAnApprovedRevokeTrustReachesTheIdentityProvider drives the whole Tier-3 chain.
func TestAnApprovedRevokeTrustReachesTheIdentityProvider(t *testing.T) {
	p := newPKI(t)
	idp := startIdP(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)

	priv, pub := signingKeypair(t)
	p.signingPriv = priv
	setDynamic(t, stack, "OPENSHIELD_IDP_ENDPOINT", "http://"+idp.addr+"/idp")
	addr := "127.0.0.1:" + freePort(t)
	srv := Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
		"OPENSHIELD_RISK_SIGNING_KEY=" + priv,
		// The responder verifies against the control plane's PUBLIC key: an intent that does not verify
		// is not from the control plane, and an unverifiable one must never disable an account.
		"OPENSHIELD_INTENT_KEY=" + pub,
		"OPENSHIELD_IDP_TOKEN=idp-secret",
	}, tlsEnv(m)...))
	waitTCP(t, addr, 90*time.Second)
	base := "https://" + addr

	alice := p.operator(t, "responder", "alice")
	bob := p.operator(t, "responder", "bob")
	q := url.Values{"verb": {"revoke-trust"}, "subject": {"subject-revoked"}, "reason": {"credential theft"}}
	code, body := do(t, alice, http.MethodPost, base+"/intents/prepare?"+q.Encode(), nil)
	if code != http.StatusOK {
		t.Fatalf("preparing: %d %s\n%s", code, body, srv.Output())
	}
	var prep struct {
		IntentIDs   []string `json:"intent_ids"`
		ApprovalIDs []int64  `json:"approval_ids"`
	}
	if err := json.Unmarshal([]byte(body), &prep); err != nil {
		t.Fatal(err)
	}

	// UNAPPROVED: nothing reaches the IdP. Asserted before the happy path, because this is the state an
	// attacker who owns the control plane's publish path would be in.
	pub1 := base + "/intents/publish?id=" + url.QueryEscape(prep.IntentIDs[0]) + "&reason=theft"
	if code, body = do(t, alice, http.MethodPost, pub1, nil); code != http.StatusForbidden {
		t.Fatalf("an unapproved REVOKE_TRUST published: %d %s", code, body)
	}
	time.Sleep(2 * time.Second)
	if idp.count() != 0 {
		t.Fatalf("an UNAPPROVED revocation reached the identity provider (%d calls) — these actions are "+
			"NOT undone by intent expiry, so a wrongly-disabled account stays disabled", idp.count())
	}

	if code, body = do(t, bob, http.MethodPost,
		base+"/approvals/resolve?id="+itoaTest(prep.ApprovalIDs[0])+"&approve=true", nil); code != http.StatusOK {
		t.Fatalf("approving: %d %s", code, body)
	}
	if code, body = do(t, alice, http.MethodPost, pub1, nil); code != http.StatusOK {
		t.Fatalf("an APPROVED revocation was refused: %d %s\n%s", code, body, srv.Output())
	}

	Eventually(t, 90*time.Second, "the approved revocation to reach the identity provider", func() bool {
		return idp.count() > 0
	})
	idp.mu.Lock()
	auth, first := idp.auth, idp.calls[0]
	idp.mu.Unlock()
	if auth != "Bearer idp-secret" {
		t.Errorf("the IdP call carried %q — an unauthenticated call to an identity provider either fails "+
			"or succeeds against an open one, and both are bad", auth)
	}
	// BOTH actions the verb maps to. Disabling an account without revoking live sessions leaves the
	// attacker signed in — the revocation would look done and change nothing for hours.
	acts := idp.actions()
	var sawDisable, sawRevoke bool
	for _, a := range acts {
		switch a {
		case "disable-user":
			sawDisable = true
		case "revoke-sessions":
			sawRevoke = true
		}
	}
	if !sawDisable || !sawRevoke {
		t.Errorf("the IdP saw %v — REVOKE_TRUST maps to disabling the user AND revoking sessions; "+
			"disabling without revoking leaves an attacker signed in", acts)
	}
	if s, _ := first["subject"].(string); s != "subject-revoked" {
		t.Errorf("the call names subject %q", s)
	}
	// The enactment is RECORDED, so "what did we do to this person" is answerable.
	pool := openPool(t, stack.DSN)
	Eventually(t, 60*time.Second, "the enactment to be recorded", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM runner_actions`).Scan(&n)
		return n > 0
	})
}

// TestAForgedIntentNeverReachesTheIdentityProvider isolates the SIGNATURE.
//
// A forged intent that disabled accounts would be the worst outcome the response system can produce: an
// attacker with broker access turning the platform into a denial-of-service against its own users, with
// actions that intent expiry does NOT undo.
//
// THE SCENARIO SEEDS AN APPROVED APPROVAL for the forged intent id, and that is the whole point of its
// design. The first version did not, and removing the signature check did NOT fail it — because
// `EnactIntent` ALSO requires a four-eyes approval bound to the intent id, and that second gate refused
// the forged message on its own. Genuine defence in depth, and a test that cannot tell which control
// fired is not testing either. Approving the forged id first removes the other gate, so what remains is
// the signature and nothing else.
func TestAForgedIntentNeverReachesTheIdentityProvider(t *testing.T) {
	p := newPKI(t)
	idp := startIdP(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)

	// The control plane trusts key A; the forger signs with key B.
	_, trustedPub := signingKeypair(t)
	forgerPriv, _ := signingKeypair(t)

	setDynamic(t, stack, "OPENSHIELD_IDP_ENDPOINT", "http://"+idp.addr+"/idp")
	srv := Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_INTENT_KEY=" + trustedPub,
	}, tlsEnv(m)...))
	srv.WaitForOutput("subscribing to telemetry", 90*time.Second)

	// Approve the forged id, so the ONLY control left standing is the signature.
	at := time.Now()
	forgedID := "INTENT_VERB_REVOKE_TRUST:subject-forged:" + strconv.FormatInt(at.Unix()/60, 10)
	pool := openPool(t, stack.DSN)
	if _, err := pool.Exec(Ctx(t),
		`INSERT INTO approvals (subject_kind, subject_id, requester, reason, state, approver, resolved_at, expires_at)
		 VALUES ('response-intent',$1,'operator:alice','forged','approved','operator:bob', now(), now() + interval '1 hour')`,
		forgedID); err != nil {
		t.Fatalf("seeding the approval: %v", err)
	}

	publishForgedIntentAt(t, stack, m, forgerPriv, "subject-forged", at)
	time.Sleep(6 * time.Second)
	if n := idp.count(); n != 0 {
		t.Errorf("a FORGED intent reached the identity provider (%d calls). Its four-eyes approval was "+
			"seeded, so the SIGNATURE is the only control that could have refused it — and it did not. "+
			"That is anything with broker access disabling any account, with actions intent expiry does "+
			"not undo\n%s", n, srv.Output())
	}
}

// publishForgedIntent puts a correctly-shaped, correctly-signed-by-the-WRONG-key intent on the broker.
//
// Signed by an untrusted key rather than malformed, deliberately: a garbage message proves the decoder
// rejects garbage. This proves the SIGNATURE is what refuses it — the property the whole channel rests
// on, and the only one an attacker with broker access has to beat.
func publishForgedIntentAt(t *testing.T, stack *Stack, m TLSMaterial, privPath, subject string, at time.Time) {
	t.Helper()
	priv, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	intent := &corev1.ResponseIntent{
		IntentId: "INTENT_VERB_REVOKE_TRUST:" + subject + ":" + strconv.FormatInt(at.Unix()/60, 10),
		Verb:     corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST,
		Subject:  subject,
		Version:  core.WireVersion,
		IssuedAt: timestamppb.New(at), ExpiresAt: timestamppb.New(at.Add(time.Hour)),
		Reason: "forged",
	}
	payload, err := proto.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := proto.Marshal(&corev1.SignedUpdate{
		Payload: payload, Signature: ed25519.Sign(ed25519.PrivateKey(priv), payload)})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := nats.Connect(stack.NATSURL, nats.ClientCert(m.Cert, m.Key), nats.RootCAs(m.CA))
	if err != nil {
		t.Fatalf("connecting to publish a forged intent: %v", err)
	}
	defer conn.Close()
	if err := conn.Publish(natsx.SubjectIntent, signed); err != nil {
		t.Fatal(err)
	}
	_ = conn.Flush()
}
