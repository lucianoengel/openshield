package controlplane_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/runner"
)

// SOAR-8(b): executing an approved intent against an EXTERNAL identity provider.
//
// This is the first action OpenShield takes outside itself, and it is IRREVERSIBLE — expiry restores a
// blocked flow and a denied exec (D253/D254), but it cannot un-revoke a session. Every assertion here is
// about a control that exists because of that asymmetry.

// idpServer is a stand-in identity provider that counts what it was asked to do.
type idpServer struct {
	*httptest.Server
	calls   atomic.Int64
	last    atomic.Value // callSeen
	failing atomic.Bool
}

type callSeen struct {
	intentHeader string
	auth         string
	body         string
}

func newIDPServer(t *testing.T) *idpServer {
	t.Helper()
	s := &idpServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		s.last.Store(callSeen{
			intentHeader: r.Header.Get("X-OpenShield-Intent"),
			auth:         r.Header.Get("Authorization"),
			body:         string(buf[:n]),
		})
		if s.failing.Load() {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.Close)
	return s
}

func idpConnector(endpoint string) *runner.Connector {
	return &runner.Connector{
		Name:     "idp",
		Endpoint: endpoint,
		Token:    "s3cret",
		Actions: map[corev1.IntentVerb][]runner.Action{
			// A per-connector CLOSED verb set: this connector handles REVOKE_TRUST and nothing else.
			corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST: {runner.ActionDisableUser, runner.ActionRevokeSessions},
		},
		Timeout: 5 * time.Second,
	}
}

func testIntent(id, subject string, verb corev1.IntentVerb, expires time.Time) *corev1.ResponseIntent {
	return &corev1.ResponseIntent{
		IntentId:  id,
		Subject:   subject,
		Verb:      verb,
		Reason:    "credential compromise",
		ExpiresAt: timestamppb.New(expires),
	}
}

// TestUnapprovedIntentIsNeverExecuted is SOAR-8's acceptance criterion, and the reason the check lives in
// the runner rather than being inherited from publication.
//
// Mutation: drop the approval check → the call happens → FAILS.
// Mutation: look the approval up by SUBJECT instead of intent id → an approval for a different intent
// authorizes this one → FAILS.
func TestUnapprovedIntentIsNeverExecuted(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	idp := newIDPServer(t)
	conn := idpConnector(idp.URL)
	ctx := context.Background()
	future := time.Now().Add(time.Hour)

	// (1) No approval at all.
	in := testIntent("intent-noapproval", "subject-a", corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST, future)
	if _, err := srv.EnactIntent(ctx, conn, in); !errors.Is(err, controlplane.ErrIntentNotApproved) {
		t.Fatalf("err = %v, want ErrIntentNotApproved", err)
	}
	if idp.calls.Load() != 0 {
		t.Fatalf("an UNAPPROVED intent made %d call(s) to the identity provider — this action cannot be "+
			"undone, and nothing authorized it", idp.calls.Load())
	}

	// (2) A PENDING approval is not an approval.
	pendingID, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent,
		"intent-pending", "cert:alice", "revoke trust", 0)
	if err != nil {
		t.Fatal(err)
	}
	pending := testIntent("intent-pending", "subject-b", corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST, future)
	if _, err := srv.EnactIntent(ctx, conn, pending); !errors.Is(err, controlplane.ErrIntentNotApproved) {
		t.Errorf("a PENDING approval authorized execution: %v", err)
	}
	if idp.calls.Load() != 0 {
		t.Errorf("a pending approval produced %d call(s)", idp.calls.Load())
	}

	// (3) A DENIED approval is not an approval.
	if err := srv.ResolveApproval(ctx, pendingID, "cert:bob", false); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.EnactIntent(ctx, conn, pending); !errors.Is(err, controlplane.ErrIntentNotApproved) {
		t.Errorf("a DENIED approval authorized execution: %v", err)
	}

	// (4) An approval for a DIFFERENT intent id does not transfer. This is what SOAR-3's (kind, id)
	// keying exists for: approval to revoke trust for one subject must never authorize another.
	otherID, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent,
		"intent-other", "cert:alice", "revoke trust", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ResolveApproval(ctx, otherID, "cert:bob", true); err != nil {
		t.Fatal(err)
	}
	elsewhere := testIntent("intent-elsewhere", "subject-c", corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST, future)
	if _, err := srv.EnactIntent(ctx, conn, elsewhere); !errors.Is(err, controlplane.ErrIntentNotApproved) {
		t.Errorf("an approval for a DIFFERENT intent authorized this one: %v", err)
	}
	if idp.calls.Load() != 0 {
		t.Fatalf("%d unauthorized call(s) reached the identity provider", idp.calls.Load())
	}
	if n := countRows(t, pool, `SELECT count(*) FROM runner_actions`); n != 0 {
		t.Errorf("%d action row(s) recorded for intents that were never executed", n)
	}
}

// TestApprovedIntentExecutesAndLinksIntentToCall — the ledger link the ticket exists to provide.
//
// Mutation: record the outcome without the target → FAILS.
func TestApprovedIntentExecutesAndLinksIntentToCall(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	idp := newIDPServer(t)
	conn := idpConnector(idp.URL)
	ctx := context.Background()

	id, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent,
		"intent-approved", "cert:alice", "revoke trust", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ResolveApproval(ctx, id, "cert:bob", true); err != nil {
		t.Fatal(err)
	}
	in := testIntent("intent-approved", "pseudo-subject-42", corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST,
		time.Now().Add(time.Hour))

	done, err := srv.EnactIntent(ctx, conn, in)
	if err != nil {
		t.Fatalf("enact: %v", err)
	}
	if done != 2 {
		t.Errorf("performed %d action(s), want 2 (disable-user and revoke-sessions)", done)
	}
	if idp.calls.Load() != 2 {
		t.Errorf("the identity provider saw %d call(s), want 2", idp.calls.Load())
	}
	seen := idp.last.Load().(callSeen)
	if seen.intentHeader != "intent-approved" {
		t.Errorf("the call carried intent header %q — a receiver's access log alone must link the call "+
			"back to what authorized it", seen.intentHeader)
	}
	if seen.auth != "Bearer s3cret" {
		t.Errorf("auth header = %q", seen.auth)
	}
	// The SUBJECT crosses as the PSEUDONYM (D23), unresolved: resolving it here would put a
	// pseudonym→identity table in the control plane.
	if !contains(seen.body, "pseudo-subject-42") {
		t.Errorf("body %q does not carry the pseudonymous subject", seen.body)
	}

	acts, err := srv.EnactmentsForIntent(ctx, "intent-approved")
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 1 {
		t.Fatalf("recorded %d action row(s), want 1 per (connector, intent)", len(acts))
	}
	a := acts[0]
	if a.State != "executed" || a.HTTPStatus != 200 {
		t.Errorf("record state=%q status=%d, want executed/200", a.State, a.HTTPStatus)
	}
	if a.Target != idp.URL {
		t.Errorf("record target = %q, want the URL that was called (%q) — an irreversible action with no "+
			"record of WHAT was called cannot be explained to the person it was applied to", a.Target, idp.URL)
	}
	if a.IntentID != "intent-approved" || a.Subject != "pseudo-subject-42" || a.Connector != "idp" {
		t.Errorf("record does not link intent→subject→connector: %+v", a)
	}
}

// TestRedeliveryExecutesExactlyOnce — at-most-once, because a duplicate "disable this account" is the
// failure that gets a SOAR turned off.
//
// Mutation: drop ON CONFLICT DO NOTHING from the claim → the second delivery calls again → FAILS.
func TestRedeliveryExecutesExactlyOnce(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	idp := newIDPServer(t)
	conn := idpConnector(idp.URL)
	ctx := context.Background()

	id, _ := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent,
		"intent-redelivered", "cert:alice", "revoke", 0)
	if err := srv.ResolveApproval(ctx, id, "cert:bob", true); err != nil {
		t.Fatal(err)
	}
	in := testIntent("intent-redelivered", "subject-r", corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST,
		time.Now().Add(time.Hour))

	if _, err := srv.EnactIntent(ctx, conn, in); err != nil {
		t.Fatal(err)
	}
	first := idp.calls.Load()
	// The same intent arrives again — a JetStream redelivery, a replayed message, a restarted subscriber.
	for i := 0; i < 3; i++ {
		if _, err := srv.EnactIntent(ctx, conn, in); !errors.Is(err, controlplane.ErrAlreadyEnacted) {
			t.Errorf("redelivery %d returned %v, want ErrAlreadyEnacted", i, err)
		}
	}
	if idp.calls.Load() != first {
		t.Errorf("redelivery made %d further call(s) — a replayed intent re-disabled an account",
			idp.calls.Load()-first)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM runner_actions WHERE intent_id='intent-redelivered'`); n != 1 {
		t.Errorf("%d action rows for one intent, want 1", n)
	}

	// CONCURRENT redelivery. The sequential case above cannot distinguish an ATOMIC claim from a
	// check-then-insert: both skip a second delivery that arrives after the first finished. Only a race
	// separates them — and a check-then-insert is what someone "simplifying" this would write.
	//
	// One race is a probabilistic detector (the lesson from D251, where an 8-way race over a single
	// subject passed a pre-check mutant because Postgres timing serialized the readers). So: 25
	// independent intents, 6 racers each.
	const intents, racers = 25, 6
	base := idp.calls.Load()
	for i := 0; i < intents; i++ {
		iid := fmt.Sprintf("intent-race-%d", i)
		aid, _ := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent, iid, "cert:alice", "revoke", 0)
		if err := srv.ResolveApproval(ctx, aid, "cert:bob", true); err != nil {
			t.Fatal(err)
		}
		raced := testIntent(iid, fmt.Sprintf("subject-race-%d", i), corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST,
			time.Now().Add(time.Hour))
		var wg sync.WaitGroup
		for r := 0; r < racers; r++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, _ = srv.EnactIntent(ctx, conn, raced) }()
		}
		wg.Wait()
	}
	// Two actions per intent, exactly once each.
	if got, want := idp.calls.Load()-base, int64(intents*2); got != want {
		t.Errorf("%d concurrent deliveries produced %d call(s), want %d — the claim is not atomic, so two "+
			"racing deliveries can both disable the same account", intents*racers, got, want)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM runner_actions WHERE intent_id LIKE 'intent-race-%'`); n != intents {
		t.Errorf("%d action rows for %d raced intents, want %d", n, intents, intents)
	}
}

// TestUndeclaredVerbAndExpiredIntentDoNothing — the closed verb set, and expiry as authority.
func TestUndeclaredVerbAndExpiredIntentDoNothing(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	idp := newIDPServer(t)
	conn := idpConnector(idp.URL)
	ctx := context.Background()

	// A verb this connector does not declare: ignored, not improvised into an action. Approved, so the
	// only thing stopping it is the closed vocabulary.
	id, _ := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent,
		"intent-contain", "cert:alice", "contain", 0)
	if err := srv.ResolveApproval(ctx, id, "cert:bob", true); err != nil {
		t.Fatal(err)
	}
	contain := testIntent("intent-contain", "subject-x", corev1.IntentVerb_INTENT_VERB_CONTAIN,
		time.Now().Add(time.Hour))
	if n, err := srv.EnactIntent(ctx, conn, contain); err != nil || n != 0 {
		t.Errorf("an undeclared verb returned n=%d err=%v, want 0 and no error", n, err)
	}
	if idp.calls.Load() != 0 {
		t.Errorf("an undeclared verb produced %d call(s) — the connector improvised an action nobody "+
			"enumerated", idp.calls.Load())
	}
	if n := countRows(t, pool, `SELECT count(*) FROM runner_actions WHERE intent_id='intent-contain'`); n != 0 {
		t.Errorf("%d row(s) recorded for a verb that did nothing — a row implies something happened", n)
	}

	// An EXPIRED intent is not authority, even with a live approval.
	eid, _ := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent,
		"intent-expired", "cert:alice", "revoke", 0)
	if err := srv.ResolveApproval(ctx, eid, "cert:bob", true); err != nil {
		t.Fatal(err)
	}
	expired := testIntent("intent-expired", "subject-y", corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST,
		time.Now().Add(-time.Minute))
	if _, err := srv.EnactIntent(ctx, conn, expired); !errors.Is(err, controlplane.ErrIntentLapsed) {
		t.Errorf("an EXPIRED intent returned %v, want ErrIntentLapsed", err)
	}
	if idp.calls.Load() != 0 {
		t.Errorf("an expired intent produced %d call(s)", idp.calls.Load())
	}
}

// TestFailedCallIsRecordedNotDiscarded: no retry, and the failure is visible against the intent id.
func TestFailedCallIsRecordedNotDiscarded(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	idp := newIDPServer(t)
	idp.failing.Store(true)
	conn := idpConnector(idp.URL)
	ctx := context.Background()

	id, _ := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent,
		"intent-failing", "cert:alice", "revoke", 0)
	if err := srv.ResolveApproval(ctx, id, "cert:bob", true); err != nil {
		t.Fatal(err)
	}
	in := testIntent("intent-failing", "subject-f", corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST,
		time.Now().Add(time.Hour))
	if _, err := srv.EnactIntent(ctx, conn, in); err == nil {
		t.Fatal("a failing identity provider reported success")
	}
	// No retry: exactly one attempt. An automatic retry of an irreversible call is how one failure
	// becomes several.
	if idp.calls.Load() != 1 {
		t.Errorf("the failing call was attempted %d times, want 1 — this action is irreversible and must "+
			"not be retried automatically", idp.calls.Load())
	}
	acts, err := srv.EnactmentsForIntent(ctx, "intent-failing")
	if err != nil || len(acts) != 1 {
		t.Fatalf("acts=%+v err=%v", acts, err)
	}
	if acts[0].State != "failed" || acts[0].Error == "" || acts[0].HTTPStatus != http.StatusBadGateway {
		t.Errorf("the failure was not recorded with its cause: %+v", acts[0])
	}
}

// TestActionVocabularyIsClosed — a third action cannot be added without editing an assertion that says why
// the set is closed.
func TestActionVocabularyIsClosed(t *testing.T) {
	want := []runner.Action{runner.ActionDisableUser, runner.ActionRevokeSessions}
	if got := runner.AllActions(); !reflect.DeepEqual(got, want) {
		t.Errorf("connector actions = %v, want exactly %v. This runner reaches into an identity provider "+
			"and takes actions expiry cannot undo; a vocabulary it can be made to extend is an open action "+
			"framework pointed at someone's account.", got, want)
	}
	conn := idpConnector("http://example.invalid")
	if acts := conn.ActionsFor(corev1.IntentVerb_INTENT_VERB_ELEVATE_SCRUTINY); len(acts) != 0 {
		t.Errorf("an undeclared verb mapped to %v", acts)
	}
	if notice := conn.IrreversibilityNotice(); !contains(notice, "IRREVERSIBLE") {
		t.Errorf("the operator notice does not state irreversibility: %q — every other intent enactment "+
			"in this platform is restored on expiry, so the reasonable generalisation is wrong here", notice)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
