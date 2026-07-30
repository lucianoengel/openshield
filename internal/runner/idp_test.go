package runner_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/runner"
)

// THE TEST THIS PACKAGE'S OWN COMMENT SAID ALREADY EXISTED.
//
// idp.go says of the Action vocabulary: "A test pins the set to exactly these two, so a third cannot be
// added without editing an assertion that says why." There was no test file in the package at all. The
// safeguard was described, relied on in the reasoning for calling the set closed, and absent.
//
// It matters more here than in most places. This package is the FIRST thing in OpenShield that acts
// outside itself, and unlike every other intent enactment its effects are irreversible — expiry cannot
// un-revoke a session. A vocabulary that can quietly grow is an open action framework reaching into an
// identity provider.
//
// So: if you are adding a third action, this assertion is the thing you must edit, and this comment is the
// argument you are answering.
func TestTheActionVocabularyIsClosed(t *testing.T) {
	got := runner.AllActions()
	want := []runner.Action{runner.ActionDisableUser, runner.ActionRevokeSessions}

	if len(got) != len(want) {
		t.Fatalf("AllActions() = %v, want exactly %v.\n\nThis set is CLOSED for the same reason the Action "+
			"set (D14), the intent verbs and the playbook step registry are: a component that can be made "+
			"to perform an operation nobody enumerated is an open action framework — and this one reaches "+
			"into an identity provider, irreversibly.", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AllActions() = %v, want %v", got, want)
		}
	}
	// The wire values are part of the contract: a receiver matches on them.
	if runner.ActionDisableUser != "disable-user" || runner.ActionRevokeSessions != "revoke-sessions" {
		t.Fatalf("the action wire values changed: %q %q", runner.ActionDisableUser, runner.ActionRevokeSessions)
	}
}

// "A verb absent from it is IGNORED — improvising an action for an unmapped verb is precisely what a closed
// vocabulary exists to prevent." An unmapped verb producing a default action would disable accounts for
// intents nobody mapped to this connector.
func TestAnUnmappedVerbProducesNoAction(t *testing.T) {
	c := &runner.Connector{
		Name: "idp",
		Actions: map[corev1.IntentVerb][]runner.Action{
			corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST: {runner.ActionDisableUser},
		},
	}
	if got := c.ActionsFor(corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST); len(got) != 1 || got[0] != runner.ActionDisableUser {
		t.Fatalf("a DECLARED verb produced %v", got)
	}
	for _, verb := range []corev1.IntentVerb{
		corev1.IntentVerb_INTENT_VERB_UNSPECIFIED,
		corev1.IntentVerb_INTENT_VERB_CONTAIN,
	} {
		if got := c.ActionsFor(verb); len(got) != 0 {
			t.Fatalf("undeclared verb %v produced %v — an unmapped verb must be ignored, not improvised", verb, got)
		}
	}

	// A nil connector and a nil map must answer "nothing", not panic: this is called while assembling a
	// response, and a panic there takes down the control plane mid-incident.
	if got := (*runner.Connector)(nil).ActionsFor(corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST); len(got) != 0 {
		t.Fatalf("a nil connector produced %v", got)
	}
	if got := (&runner.Connector{}).ActionsFor(corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST); len(got) != 0 {
		t.Fatalf("a connector with no Actions map produced %v", got)
	}
}

// The call has to carry what links it back to the authorization: the intent id in BOTH the body and a
// header, and the PSEUDONYM rather than a resolved account (D23).
func TestTheCallCarriesTheIntentIDAndThePseudonym(t *testing.T) {
	var (
		gotBody   []byte
		gotHeader string
		gotAuth   string
		gotMethod string
		calls     int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotBody, _ = io.ReadAll(r.Body)
		gotHeader = r.Header.Get("X-OpenShield-Intent")
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &runner.Connector{Name: "idp", Endpoint: srv.URL, Token: "secret-token"}
	res, err := c.Call(context.Background(), runner.ActionDisableUser, "sub_abc123", "intent-77", "beaconing")
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != http.StatusOK || res.Target != srv.URL {
		t.Fatalf("Result = %+v", res)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %s, want POST", gotMethod)
	}
	if gotHeader != "intent-77" {
		t.Fatalf("X-OpenShield-Intent = %q — a receiver's access log alone must link the call to what "+
			"authorized it", gotHeader)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}

	var body struct {
		Action, Subject, IntentID, Reason string
	}
	if err := json.Unmarshal(gotBody, &struct {
		Action   *string `json:"action"`
		Subject  *string `json:"subject"`
		IntentID *string `json:"intent_id"`
		Reason   *string `json:"reason"`
	}{&body.Action, &body.Subject, &body.IntentID, &body.Reason}); err != nil {
		t.Fatalf("body did not parse: %v (%s)", err, gotBody)
	}
	if body.Action != "disable-user" || body.IntentID != "intent-77" || body.Reason != "beaconing" {
		t.Fatalf("body = %+v", body)
	}
	// THE SUBJECT STAYS PSEUDONYMOUS. Resolving it here would need a pseudonym→identity table inside the
	// control plane, which is the re-identification surface this design exists to avoid (D23).
	if body.Subject != "sub_abc123" {
		t.Fatalf("subject = %q, want the pseudonym passed through unresolved", body.Subject)
	}
	if calls != 1 {
		t.Fatalf("the endpoint was called %d times", calls)
	}
}

// "It does not retry: an automatic retry of an irreversible call is how one failure becomes several."
func TestAFailedCallIsNotRetried(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusForbidden, http.StatusTeapot, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(status)
			}))
			defer srv.Close()

			c := &runner.Connector{Name: "idp", Endpoint: srv.URL}
			res, err := c.Call(context.Background(), runner.ActionRevokeSessions, "sub_x", "i-1", "")
			if err == nil {
				t.Fatal("a non-2xx response was reported as success")
			}
			if calls != 1 {
				t.Fatalf("the endpoint was called %d times — an irreversible action must not be retried "+
					"automatically; one failure would become several", calls)
			}
			// The status is still reported, because the durable record needs to say what happened.
			if res.Status != status {
				t.Fatalf("Result.Status = %d, want %d recorded even on failure", res.Status, status)
			}
			if res.Target != srv.URL {
				t.Fatalf("Result.Target = %q, want the URL that was called recorded even on failure", res.Target)
			}
		})
	}
}

func TestCallIsBoundedByItsTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer func() { close(release); srv.Close() }()

	c := &runner.Connector{Name: "idp", Endpoint: srv.URL, Timeout: 150 * time.Millisecond}
	start := time.Now()
	if _, err := c.Call(context.Background(), runner.ActionDisableUser, "sub_x", "i-1", ""); err == nil {
		t.Fatal("a hanging receiver returned success")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Call took %v against a hanging receiver — an unbounded call holds the response path open", elapsed)
	}
}

// The notice exists because "a reasonable generalisation from every other intent enactment is WRONG here":
// everything else in the platform is restored when the intent lapses. An operator reading this must see
// which system, and that expiry restores nothing.
func TestTheIrreversibilityNoticeNamesTheTargetAndSaysExpiryRestoresNothing(t *testing.T) {
	c := &runner.Connector{
		Name:     "okta-prod",
		Endpoint: "https://idp.internal/soar",
		Actions: map[corev1.IntentVerb][]runner.Action{
			corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST: {runner.ActionDisableUser, runner.ActionRevokeSessions},
		},
	}
	notice := c.IrreversibilityNotice()
	for _, must := range []string{"okta-prod", "https://idp.internal/soar", "IRREVERSIBLE", "expiry"} {
		if !strings.Contains(notice, must) {
			t.Fatalf("the startup notice does not mention %q: %s", must, notice)
		}
	}
	for _, a := range []string{"disable-user", "revoke-sessions"} {
		if !strings.Contains(notice, a) {
			t.Fatalf("the notice does not name the action %q an operator is consenting to: %s", a, notice)
		}
	}
}
