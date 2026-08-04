package controlplane_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SEC-D: four-eyes is exactly as strong as the deployment's ability to tell two operators apart, and it
// used to say nothing about that.
//
// The approver≠requester comparison is sound and lives in the UPDATE predicate. What it compares is an
// identity STRING, and two shipped defaults decide what one is worth: OPENSHIELD_OPERATOR_ROLES_STRICT=0
// lets an identity with no server-side row fall back to its certificate (two operator certs are two
// operators), and OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP=0 accepts an unbound token (two stolen tokens
// are two operators).
//
// The harm is specific: an approval recorded on such a deployment reads, forever, as "alice requested,
// bob approved" — an audit trail attesting to a two-person control that may never have existed. That is
// worse than not offering the control, because the trail is what an investigation later relies on.

// hardened turns both operator-identity switches on for one test.
func hardened(t *testing.T) {
	t.Helper()
	t.Setenv("OPENSHIELD_OPERATOR_ROLES_STRICT", "1")
	t.Setenv("OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP", "1")
}

func requestAndResolve(t *testing.T, srv *controlplane.Server, subject, approver string, approve bool) error {
	t.Helper()
	ctx := context.Background()
	id, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent, subject,
		"cert:alice", "contain host A", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return srv.ResolveApproval(ctx, id, approver, approve)
}

// TestAnApprovalRecordsWhatFourEyesWasWorth is the fix: the trail states the assurance in force at the
// moment of resolution, so it can never be read as claiming more than the deployment could deliver.
//
// Mutation: stop writing the column (drop `assurance = $4` from the UPDATE) → both cases read back
// empty → this FAILS.
func TestAnApprovalRecordsWhatFourEyesWasWorth(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	// A deployment running the shipped defaults.
	t.Setenv("OPENSHIELD_OPERATOR_ROLES_STRICT", "0")
	t.Setenv("OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP", "0")
	if err := requestAndResolve(t, srv, "intent-weak", "cert:bob", true); err != nil {
		t.Fatalf("a second operator's approval was refused on an unhardened deployment: %v — recording "+
			"the weakness must not break the control", err)
	}
	got, err := srv.ApprovalFor(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-weak")
	if err != nil {
		t.Fatal(err)
	}
	if got.Assurance != controlplane.AssuranceWeak {
		t.Errorf("assurance = %q, want %q — an approval on a deployment where two credentials are two "+
			"operators reads as two people unless the row says otherwise",
			got.Assurance, controlplane.AssuranceWeak)
	}

	// The same control on a hardened deployment.
	hardened(t)
	if err := requestAndResolve(t, srv, "intent-strong", "cert:bob", true); err != nil {
		t.Fatal(err)
	}
	got, err = srv.ApprovalFor(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-strong")
	if err != nil {
		t.Fatal(err)
	}
	if got.Assurance != controlplane.AssuranceStrong {
		t.Errorf("assurance = %q on a hardened deployment, want %q — an operator who has done the work "+
			"must be able to see that it counted", got.Assurance, controlplane.AssuranceStrong)
	}
}

// TestADeploymentCanRefuseAWeakApproval. The strongest posture, opt-in.
//
// Mutation: make RequireStrongFourEyes always false, or drop the check → the approval succeeds → this
// FAILS.
func TestADeploymentCanRefuseAWeakApproval(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	t.Setenv("OPENSHIELD_OPERATOR_ROLES_STRICT", "0")
	t.Setenv("OPENSHIELD_FOUR_EYES_REQUIRE_STRONG", "1")

	err := requestAndResolve(t, srv, "intent-refused", "cert:bob", true)
	if !errors.Is(err, controlplane.ErrWeakFourEyes) {
		t.Fatalf("err = %v, want ErrWeakFourEyes — this deployment asked to refuse approvals it cannot "+
			"attest to", err)
	}
	// AND IT STAYS PENDING. A refusal that quietly resolved the request would be worse than allowing it:
	// the dangerous thing would be recorded as decided by a control that declined to act.
	got, err := srv.ApprovalFor(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-refused")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != controlplane.ApprovalPending {
		t.Errorf("state = %q after a refused approval, want still pending", got.State)
	}

	// Hardening the deployment lets the same approval through — the refusal is about the identity model,
	// not about this request.
	hardened(t)
	if err := srv.ResolveApproval(ctx, got.ID, "cert:bob", true); err != nil {
		t.Fatalf("the approval was still refused after hardening: %v", err)
	}
}

// TestADenialIsNeverGatedByAssurance.
//
// Gating a "no" would invert the control: the pending request — a containment, a fleet-wide disable, a
// case closure — stays alive and approvable, and the operator trying to shut it down is the one refused.
// A hardening switch must not become a way of keeping dangerous things pending.
//
// Mutation: drop the `approve &&` from the gate → the denial is refused → this FAILS.
func TestADenialIsNeverGatedByAssurance(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	t.Setenv("OPENSHIELD_OPERATOR_ROLES_STRICT", "0")
	t.Setenv("OPENSHIELD_FOUR_EYES_REQUIRE_STRONG", "1")

	if err := requestAndResolve(t, srv, "intent-denied", "cert:bob", false); err != nil {
		t.Fatalf("a DENIAL was refused on a weak deployment: %v — the request would stay pending and "+
			"approvable, and the operator trying to stop it is the one being blocked", err)
	}
	got, err := srv.ApprovalFor(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-denied")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != controlplane.ApprovalDenied {
		t.Errorf("state = %q, want denied", got.State)
	}
	// The denial is still recorded as weak — the identity of whoever denied it is no better established
	// than anyone else's, and the row must not imply otherwise.
	if got.Assurance != controlplane.AssuranceWeak {
		t.Errorf("assurance = %q on a denial, want %q", got.Assurance, controlplane.AssuranceWeak)
	}
}

// TestTheStartupNoticeNamesTheSwitchThatIsOff. A warning that says "identity is weak" without naming the
// knob is a warning that gets acknowledged and left alone.
//
// Mutation: collapse the two gaps into one generic sentence → the DPoP-only case names ROLES_STRICT and
// this FAILS.
func TestTheStartupNoticeNamesTheSwitchThatIsOff(t *testing.T) {
	t.Run("only DPoP missing", func(t *testing.T) {
		t.Setenv("OPENSHIELD_OPERATOR_ROLES_STRICT", "1")
		t.Setenv("OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP", "0")
		a := controlplane.AssessFourEyes()
		if a.Strong() {
			t.Fatal("a deployment accepting unbound operator tokens reported STRONG four-eyes")
		}
		notice := controlplane.FourEyesStartupNotice(a)
		if !strings.Contains(notice, "OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP") {
			t.Errorf("the notice does not name the switch that is off: %q", notice)
		}
		if strings.Contains(notice, "OPENSHIELD_OPERATOR_ROLES_STRICT") {
			t.Errorf("the notice names a switch that IS on, which sends an operator to fix the wrong "+
				"thing: %q", notice)
		}
	})

	t.Run("only roles missing", func(t *testing.T) {
		t.Setenv("OPENSHIELD_OPERATOR_ROLES_STRICT", "0")
		t.Setenv("OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP", "1")
		notice := controlplane.FourEyesStartupNotice(controlplane.AssessFourEyes())
		if !strings.Contains(notice, "OPENSHIELD_OPERATOR_ROLES_STRICT") {
			t.Errorf("the notice does not name the switch that is off: %q", notice)
		}
	})

	t.Run("hardened", func(t *testing.T) {
		hardened(t)
		a := controlplane.AssessFourEyes()
		if !a.Strong() {
			t.Fatalf("a fully hardened deployment reported %q", a.Level)
		}
		if notice := controlplane.FourEyesStartupNotice(a); !strings.Contains(notice, "STRONG") {
			t.Errorf("a hardened deployment gets no confirmation: %q — a message that appears only on "+
				"failure cannot be used to verify success", notice)
		}
	})
}
