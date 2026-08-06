package controlplane_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// CONSOLE-1: the admin tier fused "can change configuration" to "can read every subject's personal
// data", and one person held both because there was nowhere else to put the second.
//
// These tests assert the separation FROM BOTH SIDES, which is the only way to assert a separation. One
// direction alone is satisfiable by a grant that authorizes nothing: a role that reaches neither surface
// passes "the admin cannot export subject data" perfectly.

// grantOperator records a grant and returns a request builder for that operator's credential.
//
// THE CERTIFICATE CARRIES `agent`, WHICH RANKS AT NOTHING, deliberately. The role in force comes from
// the database, and an unrecognised OU means the legacy certificate fallback cannot supply one. So every
// success below is proof the recorded grant was read — not proof that a certificate quietly still
// decides authorization, which is the defect ZT-7 removed and which a helpfully-matching OU would hide.
func grantOperator(t *testing.T, s *controlplane.Server, ca *oneCA, cn, grant string) func(string) *http.Request {
	t.Helper()
	ctx := context.Background()
	principal := "cert:" + cn
	t.Cleanup(func() {
		pool := requireDB(t)
		_, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, principal)
	})
	if err := s.SetOperatorRole(ctx, principal, grant, "test"); err != nil {
		t.Fatalf("granting %q to %s: %v", grant, principal, err)
	}
	return func(path string) *http.Request {
		return certReq(t, ca, http.MethodGet, path, cn, "agent")
	}
}

// TestAConfigurationAdminCannotExportSubjectData — the first direction.
//
// `/subject` compiles everything the platform holds about one named human. Until this split it sat at
// the ANALYST tier, so every role above it reached the dossier as a side effect of being able to read
// the alert queue.
//
// Mutation: let a tier satisfy the privacy requirement (`return g.Privacy || roleRank(g.Tier) >=
// roleRank(RoleAdmin)`) → the admin is served and this FAILS.
func TestAConfigurationAdminCannotExportSubjectData(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ca := newOneCA(t)

	admin := grantOperator(t, s, ca, "cfg-admin", controlplane.RoleAdmin)
	gate := controlplane.RequirePrivacyOfficerForTestHandler(s, s.OperatorReadHandler())

	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, admin("/subject?id=subject-privacy-split"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an admin reached the DSAR export: %d %q — the tier that changes configuration must not "+
			"also be the tier that compiles a dossier on a named person",
			rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	// THE REFUSAL MUST SAY WHY, because this one is counter-intuitive: the operator being refused holds
	// the highest tier there is, and a message telling them their tier is too low sends them looking for
	// a tier that does not exist.
	if body := rec.Body.String(); !strings.Contains(body, "privacy officer") {
		t.Errorf("the refusal does not name the authority that is missing: %q", strings.TrimSpace(body))
	}

	// The same admin still administers. Without this the test above would pass on a credential that
	// reaches nothing at all, and would keep passing if the grant were silently broken.
	//
	// ADMITTED BY THE GATE is the claim, not 200: this fixture has no settings store installed, so the
	// configuration handler answers 503. That it answered AT ALL is the proof — an unauthorized caller
	// never reaches it.
	rec = httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(s, controlplane.RoleAdmin, s.OperatorReadHandler()).
		ServeHTTP(rec, admin("/config"))
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("the admin was refused the configuration surface too (%d %q) — this credential proves "+
			"nothing about the split", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

// TestAPrivacyOfficerCannotChangeConfiguration — the other direction, and the one that makes the
// oversight real. An officer who could turn detection off would be overseeing a system they can also
// quietly disable.
//
// Mutation: rank privacy-officer as a tier (add it to roleRank above admin, or make the tier branch
// fall through to `g.Privacy`) → the officer reads configuration and this FAILS.
func TestAPrivacyOfficerCannotChangeConfiguration(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ca := newOneCA(t)

	officer := grantOperator(t, s, ca, "data-protection-officer", controlplane.RolePrivacyOfficer)

	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(s, controlplane.RoleAdmin, s.OperatorReadHandler()).
		ServeHTTP(rec, officer("/config"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the privacy officer reached configuration: %d %q", rec.Code,
			strings.TrimSpace(rec.Body.String()))
	}
	// Not even the lowest tier. The privacy authority is not a rank, so it does not carry the alert queue
	// with it — an oversight role that could read every investigation would be a widening dressed as a
	// separation.
	rec = httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(s, controlplane.RoleAnalyst, s.OperatorReadHandler()).
		ServeHTTP(rec, officer("/alerts"))
	if rec.Code != http.StatusForbidden {
		t.Errorf("the privacy officer reached the analyst queue: %d — the second axis must not quietly "+
			"grant a tier", rec.Code)
	}

	// AND THEY CAN DO THEIR JOB. Same reason as the mirror assertion above: a credential that reaches
	// nothing satisfies every refusal in this file.
	rec = httptest.NewRecorder()
	controlplane.RequirePrivacyOfficerForTestHandler(s, s.OperatorReadHandler()).
		ServeHTTP(rec, officer("/subject?id=subject-privacy-split"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the privacy officer could not run a DSAR export (%d %q) — this credential proves "+
			"nothing about the split", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

// TestTheUpgradedAdminHoldsBothAndCanBeNarrowed is what migration 049 leaves behind, exercised through
// the same gates.
//
// The upgrade grants every existing admin `admin,privacy-officer` so no access is taken away by a
// release nobody read the notes for. THE SEPARATION IS THEREFORE AVAILABLE AND NOT IN FORCE, and the
// thing that has to work is the narrowing: `operator-role set <identity> admin` must REPLACE the grant,
// not merge into it. An authority that can only ever be added is not one that can be separated.
//
// Mutation: make SetOperatorRole merge (`privacy_officer = operator_roles.privacy_officer OR EXCLUDED…`)
// → the narrowed admin still reaches /subject and this FAILS.
func TestTheUpgradedAdminHoldsBothAndCanBeNarrowed(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ca := newOneCA(t)
	ctx := context.Background()

	both := grantOperator(t, s, ca, "upgraded-admin", "admin,privacy-officer")
	privacy := controlplane.RequirePrivacyOfficerForTestHandler(s, s.OperatorReadHandler())

	rec := httptest.NewRecorder()
	privacy.ServeHTTP(rec, both("/subject?id=subject-privacy-split"))
	if rec.Code != http.StatusOK {
		t.Fatalf("an upgraded admin lost the DSAR export the previous release gave them: %d %q — an "+
			"upgrade must not remove access silently", rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	// The listing shows the whole grant, in the form the command accepts. An access review reads this.
	rows, err := s.ListOperatorRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var listed string
	for _, r := range rows {
		if r.Identity == "cert:upgraded-admin" {
			listed = r.Role
		}
	}
	if listed != "admin,privacy-officer" {
		t.Errorf("operator-role list shows %q, want %q — a listing that omits an axis of authority is a "+
			"review that cannot see it", listed, "admin,privacy-officer")
	}

	// Now narrow them, which is the whole point of shipping the fused grant.
	if err := s.SetOperatorRole(ctx, "cert:upgraded-admin", controlplane.RoleAdmin, "test"); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	privacy.ServeHTTP(rec, both("/subject?id=subject-privacy-split"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("re-granting `admin` left the privacy authority in place (%d) — then the separation can "+
			"never be applied to any deployment that upgraded", rec.Code)
	}
}

// TestTheViewAuditIsReadableAtLast wires up the record of who looked.
//
// The control plane has recorded every investigation view since D20/T-013 and NOTHING COULD READ IT:
// `Views` and `ViewsBy` had no caller outside their own tests. An accountability record nobody can read
// accounts to nobody — the unwired shape this repo keeps finding.
//
// It is the privacy officer's route rather than the admin's on purpose: the tier that does the looking
// must not be the tier that reviews the looking.
//
// Mutation: drop the `mux.HandleFunc("/views", …)` registration → 404 and this FAILS. Mutation: mount it
// behind requireTier(RoleAdmin) → the officer is refused and this FAILS.
func TestTheViewAuditIsReadableAtLast(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ca := newOneCA(t)
	ctx := context.Background()

	const subject = "subject-who-looked"
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM investigation_views WHERE subject_filter = $1`, subject)
	})
	// An analyst looked at this subject's case. That is the fact the officer must be able to find.
	if err := s.RecordView(ctx, controlplane.ViewRecord{
		Viewer: "cert:curious-analyst", SubjectFilter: subject, Route: "/cases",
	}); err != nil {
		t.Fatal(err)
	}

	officer := grantOperator(t, s, ca, "dpo-reader", controlplane.RolePrivacyOfficer)
	gate := controlplane.RequirePrivacyOfficerForTestHandler(s, s.OperatorReadHandler())

	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, officer("/views?viewer=cert:curious-analyst"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the view audit answered %d %q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var got struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, row := range got.Rows {
		if row["subject_filter"] == subject {
			found = true
		}
	}
	if !found {
		t.Fatalf("the analyst's view of %q is not in the audit the officer reads: %v", subject, got.Rows)
	}

	// READING THE AUDIT IS ITSELF AUDITED. Nobody is above the record, including whoever holds this
	// route — otherwise the one credential that can see all the looking is the one whose looking is
	// invisible.
	own, err := s.ViewsBy(ctx, "cert:dpo-reader")
	if err != nil {
		t.Fatal(err)
	}
	if len(own) == 0 {
		t.Error("the privacy officer read the view audit and left no trace of doing so")
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM investigation_views WHERE viewer = $1`, "cert:dpo-reader")
	})
}

// TestAGrantIsRefusedRatherThanGuessed. The CLI hands a human's typing straight to SetOperatorRole.
func TestAGrantIsRefusedRatherThanGuessed(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()

	for _, spec := range []string{
		"",                      // nothing
		"root",                  // a role from a different system
		"analyst,admin",         // two tiers: taking the higher one silently turns a typo into an escalation
		"operator",              // the legacy fused role cannot be newly granted
		"admin,privacy_officer", // an underscore is not the spelling the listing prints
	} {
		if err := s.SetOperatorRole(ctx, "cert:typo-victim", spec, "test"); err == nil {
			t.Errorf("SetOperatorRole accepted %q", spec)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, "cert:typo-victim")
	})
	// Order does not matter, and the canonical form is what comes back out.
	if err := s.SetOperatorRole(ctx, "cert:typo-victim", "privacy-officer,analyst", "test"); err != nil {
		t.Fatalf("a tier and the privacy authority in the other order was refused: %v", err)
	}
	rows, err := s.ListOperatorRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Identity == "cert:typo-victim" && r.Role != "analyst,privacy-officer" {
			t.Errorf("stored grant lists as %q, want the canonical %q", r.Role, "analyst,privacy-officer")
		}
	}
}
