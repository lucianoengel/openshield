package controlplane_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// CONSOLE-1: the machine principal had a namespace and no credential.
//
// `svc:<name>` parsed, could be granted a tier and was refused four-eyes — and nothing could present
// one, because authentication minted `cert:` from a certificate and `oidc:` from a token and had no
// third path. So every `svc:` grant authorized a caller that could not exist, and every automation
// calling the operator API ran on a HUMAN's credential. That is the precise input the four-eyes account
// comparison exists to reject.

// machineReq builds a request carrying a machine token.
func machineReq(method, path, token string) *http.Request {
	return tokenReq(method, path, token)
}

// issueMachine mints a credential and grants it a tier, cleaning up both.
func issueMachine(t *testing.T, s *controlplane.Server, name, role string, ttl time.Duration) string {
	t.Helper()
	ctx := context.Background()
	pool := requireDB(t)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM machine_credentials WHERE principal = $1`, "svc:"+name)
		_, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, "svc:"+name)
	})
	tok, err := s.IssueMachineCredential(ctx, name, ttl, "test")
	if err != nil {
		t.Fatalf("issuing svc:%s: %v", name, err)
	}
	if role != "" {
		if err := s.SetOperatorRole(ctx, "svc:"+name, role, "test"); err != nil {
			t.Fatal(err)
		}
	}
	return tok
}

// TestAnIssuedMachineCredentialAuthenticatesAndIsAttributed is the acceptance case: the automation calls
// the operator API AS ITSELF.
//
// Mutation: drop the machine branch from authenticateOperator → the token falls through to the OIDC
// verifier, which is nil here, and this FAILS with 401.
func TestAnIssuedMachineCredentialAuthenticatesAndIsAttributed(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()

	tok := issueMachine(t, s, "backup-runner", controlplane.RoleResponder, time.Hour)
	if !strings.HasPrefix(tok, controlplane.MachineTokenPrefix) {
		t.Errorf("the token does not carry the %q prefix: %q — the prefix is what stops authentication "+
			"guessing which verifier owns a bearer credential, and what makes a leaked secret findable",
			controlplane.MachineTokenPrefix, tok)
	}

	// /cases/open attributes the case to the caller, so this exercises authentication AND attribution.
	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(s, controlplane.RoleResponder, s.OperatorReadHandler()).
		ServeHTTP(rec, machineReq(http.MethodPost, "/cases/open?subject=subject-machine", tok))
	if rec.Code != http.StatusOK {
		t.Fatalf("an issued machine credential could not act: %d %q", rec.Code,
			strings.TrimSpace(rec.Body.String()))
	}

	// ATTRIBUTED AS A MACHINE, not as whoever issued it. An automation whose acts are recorded under a
	// person's name is the audit-trail half of the same defect.
	var found bool
	rows, err := pool.Query(ctx, `SELECT opened_by FROM cases WHERE subject_id = $1`, "subject-machine")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var by string
		if err := rows.Scan(&by); err != nil {
			t.Fatal(err)
		}
		if by == "svc:backup-runner" {
			found = true
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM cases WHERE subject_id = $1`, "subject-machine")
	})
	if !found {
		t.Error("the case was not attributed to svc:backup-runner")
	}
}

// TestAMachineCredentialMustExpire. The whole lifecycle rests on this: everything else is optional if a
// credential can be issued once and live forever.
//
// Mutation: remove the ttl <= 0 branch, or the ceiling → the corresponding case succeeds and this FAILS.
func TestAMachineCredentialMustExpire(t *testing.T) {
	s := controlplane.New(requireDB(t))
	ctx := context.Background()

	for _, ttl := range []time.Duration{0, -time.Hour, controlplane.MaxMachineCredentialTTL + time.Minute} {
		if _, err := s.IssueMachineCredential(ctx, "eternal", ttl, "test"); !errors.Is(err,
			controlplane.ErrMachineCredentialExpiry) {
			t.Errorf("IssueMachineCredential(ttl=%s) = %v, want ErrMachineCredentialExpiry", ttl, err)
		}
	}
	// The boundary is allowed — a ceiling that refuses its own maximum is a ceiling nobody can use.
	if _, err := s.IssueMachineCredential(ctx, "at-the-ceiling", controlplane.MaxMachineCredentialTTL,
		"test"); err != nil {
		t.Errorf("the maximum TTL was refused: %v", err)
	}
	_, _ = requireDB(t).Exec(ctx, `DELETE FROM machine_credentials WHERE principal = $1`,
		"svc:at-the-ceiling")
}

// TestAnExpiredOrRevokedMachineCredentialAuthenticatesNothing.
//
// EXPIRY IS ENFORCED AT AUTHENTICATION, not by a sweeper — an expiry that needs a background job to hold
// is an expiry that stops holding while the job is down.
//
// Mutation: drop the `now.Before(expires)` check, or the `revoked` check → the matching case is served
// and this FAILS.
func TestAnExpiredOrRevokedMachineCredentialAuthenticatesNothing(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()

	gate := controlplane.RequireTierForTestHandler(s, controlplane.RoleAnalyst, s.OperatorReadHandler())
	code := func(tok string) int {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, machineReq(http.MethodGet, "/alerts", tok))
		return rec.Code
	}

	// EXPIRED. Issued live, then aged past its life directly in the table — the credential is unchanged,
	// only time has passed, which is the situation being tested.
	expired := issueMachine(t, s, "stale-runner", controlplane.RoleAnalyst, time.Hour)
	if c := code(expired); c != http.StatusOK {
		t.Fatalf("the credential did not work BEFORE expiry (%d) — then the assertion below proves "+
			"nothing about expiry", c)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE machine_credentials SET expires_at = now() - interval '1 second' WHERE principal = $1`,
		"svc:stale-runner"); err != nil {
		t.Fatal(err)
	}
	if c := code(expired); c != http.StatusUnauthorized {
		t.Errorf("an EXPIRED machine credential got %d, want 401", c)
	}

	// REVOKED, through the real command path.
	revoked := issueMachine(t, s, "fired-runner", controlplane.RoleAnalyst, time.Hour)
	if c := code(revoked); c != http.StatusOK {
		t.Fatalf("the credential did not work BEFORE revocation (%d)", c)
	}
	if err := s.RevokeMachineCredential(ctx, "fired-runner", "test"); err != nil {
		t.Fatal(err)
	}
	if c := code(revoked); c != http.StatusUnauthorized {
		t.Errorf("a REVOKED machine credential got %d, want 401", c)
	}
	// Revoking twice is not an error: the second caller wanted the same end state.
	if err := s.RevokeMachineCredential(ctx, "fired-runner", "test"); err != nil {
		t.Errorf("revoking an already-revoked credential errored: %v", err)
	}
	// ...but revoking one that never existed IS, or a typo reports success.
	if err := s.RevokeMachineCredential(ctx, "never-existed", "test"); !errors.Is(err,
		controlplane.ErrNoMachineCredential) {
		t.Errorf("revoking an unknown credential = %v, want ErrNoMachineCredential", err)
	}
}

// TestRotationInvalidatesThePreviousSecretImmediately. No overlap window, stated as a decision.
//
// Mutation: have RotateMachineCredential insert a second row instead of updating → the old secret still
// authenticates and this FAILS. Mutation: let rotate CREATE when the name is unknown → the last case
// FAILS.
func TestRotationInvalidatesThePreviousSecretImmediately(t *testing.T) {
	s := controlplane.New(requireDB(t))
	ctx := context.Background()

	gate := controlplane.RequireTierForTestHandler(s, controlplane.RoleAnalyst, s.OperatorReadHandler())
	code := func(tok string) int {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, machineReq(http.MethodGet, "/alerts", tok))
		return rec.Code
	}

	old := issueMachine(t, s, "rotating-runner", controlplane.RoleAnalyst, time.Hour)
	if c := code(old); c != http.StatusOK {
		t.Fatalf("the original secret did not work: %d", c)
	}
	fresh, err := s.RotateMachineCredential(ctx, "rotating-runner", time.Hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	if fresh == old {
		t.Fatal("rotation returned the same secret")
	}
	if c := code(fresh); c != http.StatusOK {
		t.Errorf("the rotated secret does not work: %d", c)
	}
	if c := code(old); c != http.StatusUnauthorized {
		t.Errorf("the PREVIOUS secret still authenticates after rotation (%d) — two live secrets for one "+
			"identity is the state rotation exists to end", c)
	}
	// The grant survives rotation: rotating a secret is not a re-authorization.
	rows, err := s.ListMachineCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Principal == "svc:rotating-runner" && r.Rotations != 1 {
			t.Errorf("rotations = %d, want 1 — a review cannot tell a maintained credential from a "+
				"forgotten one without it", r.Rotations)
		}
	}

	if _, err := s.RotateMachineCredential(ctx, "typo-runner", time.Hour, "test"); !errors.Is(err,
		controlplane.ErrNoMachineCredential) {
		t.Errorf("rotating an unknown name = %v, want ErrNoMachineCredential — otherwise a typo mints a "+
			"credential for a principal nobody meant to create, and reports success", err)
	}
}

// TestAMachineCredentialGrantsNothingByItself. Issuance and authorization stay separate, so there is one
// answer to "what may this caller do" rather than two.
//
// Mutation: have IssueMachineCredential also write an operator_roles row → this FAILS.
func TestAMachineCredentialGrantsNothingByItself(t *testing.T) {
	s := controlplane.New(requireDB(t))

	tok := issueMachine(t, s, "ungranted-runner", "", time.Hour)
	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(s, controlplane.RoleAnalyst, s.OperatorReadHandler()).
		ServeHTTP(rec, machineReq(http.MethodGet, "/alerts", tok))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a machine credential with no grant reached the analyst queue: %d %q — issuing a "+
			"credential must not be where authorization is decided", rec.Code,
			strings.TrimSpace(rec.Body.String()))
	}
	// 403 and not 401: it AUTHENTICATED. The distinction is what tells an operator to grant a role rather
	// than to re-issue the token.
}

// TestAMachineTokenIsNeverOfferedToTheIdentityProvider.
//
// Both credential classes arrive on the same header. A machine token that fell through to the OIDC
// verifier would fail there with a message about the identity provider — sending whoever debugs it to
// the wrong system — and on a deployment with SSO unconfigured a valid machine credential would be
// refused for the unrelated reason that there is no verifier.
//
// Mutation: check the machine branch AFTER the OIDC branch, or fall through on failure → the stub sees
// the machine token and this FAILS.
func TestAMachineTokenIsNeverOfferedToTheIdentityProvider(t *testing.T) {
	s := controlplane.New(requireDB(t))
	tok := issueMachine(t, s, "prefix-runner", controlplane.RoleAnalyst, time.Hour)

	// A verifier that accepts ANYTHING and reports a wildly different subject. If the machine token ever
	// reaches it, the caller becomes someone else entirely.
	s.SetOperatorOIDC(stubVerifier{token: tok, subject: "an-impostor"})

	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(s, controlplane.RoleAnalyst, s.OperatorReadHandler()).
		ServeHTTP(rec, machineReq(http.MethodGet, "/alerts", tok))
	if rec.Code != http.StatusOK {
		t.Fatalf("the machine credential was refused: %d %q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	// The proof: it was served under the MACHINE's grant. `oidc:https://idp.test#an-impostor` has no row,
	// so had the identity provider decided this request it would have been 403.

	// ...and a revoked machine token does not get a second opinion from the identity provider either.
	if err := s.RevokeMachineCredential(context.Background(), "prefix-runner", "test"); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(s, controlplane.RoleAnalyst, s.OperatorReadHandler()).
		ServeHTTP(rec, machineReq(http.MethodGet, "/alerts", tok))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a REVOKED machine token was re-verified by the identity provider (%d) — a revocation "+
			"must not be appealable to a system that knows nothing about it", rec.Code)
	}
}
