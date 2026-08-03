package controlplane

import (
	"errors"
	"os"
	"strings"
)

// FOUR-EYES IS EXACTLY AS STRONG AS THE DEPLOYMENT'S ABILITY TO TELL TWO OPERATORS APART (SEC-D).
//
// The control itself is sound: the approver≠requester comparison lives in the UPDATE predicate, so two
// operators racing cannot both succeed. What that comparison compares is an IDENTITY STRING, and two
// shipped defaults decide how much an identity string is worth:
//
//   - OPENSHIELD_OPERATOR_ROLES_STRICT defaults to 0, so an identity with no server-side record falls
//     back to the role in its CERTIFICATE. Whoever obtains two operator certificates is both pairs of
//     eyes, and neither of them has to exist in any table the deployment controls.
//   - OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP defaults to 0, so an operator bearer token that is not
//     sender-constrained is accepted. Two stolen tokens are two operators.
//
// Both defaults are individually correct and were argued for on their own terms: turning either on
// before a deployment has migrated locks every operator out, including the admin who would fix it. The
// defect is not the defaults. It is that four-eyes said nothing about them — an approval recorded on a
// deployment where four eyes are one credential is an audit trail attesting to a control that did not
// exist, and that is worse than having declined to offer the control at all.
//
// So this package does three things it did not do before, in increasing order of strength:
//
//  1. It can SAY what the deployment's four-eyes is worth, at startup, without being asked.
//  2. It RECORDS that assessment on the approval row, at the moment of resolution. The trail then says
//     what the control actually was, forever, and cannot be reinterpreted later by someone reading the
//     current configuration of a deployment that has since been hardened — or loosened.
//  3. It can REFUSE, for a deployment that has decided a weak approval is not an approval.

// Assurance levels recorded on an approval. Strings rather than a bool because this is written into an
// audit row that outlives the code, and a column of `t`/`f` is a column nobody can interpret in five
// years without finding this file.
const (
	// AssuranceStrong means both operator-identity hardening switches are on: an identity must exist
	// server-side, and an operator token must be sender-constrained.
	AssuranceStrong = "strong"
	// AssuranceWeak means at least one is off, so two credentials may be two "operators".
	AssuranceWeak = "weak"
)

// ErrWeakFourEyes refuses an approval on a deployment whose identities are not hardened, for a
// deployment that has asked to be refused (OPENSHIELD_FOUR_EYES_REQUIRE_STRONG=1).
var ErrWeakFourEyes = errors.New("controlplane: four-eyes requires hardened operator identity")

// FourEyesAssurance is what a two-person control is worth on this deployment, and why.
type FourEyesAssurance struct {
	Level string
	// Gaps names each switch that is not hardened, in the operator's own vocabulary — the env var to
	// set. A warning that says "identity is weak" and not which knob to turn is a warning that gets
	// acknowledged and left alone.
	Gaps []string
}

// Strong reports whether both hardening switches are on.
func (a FourEyesAssurance) Strong() bool { return a.Level == AssuranceStrong }

// AssessFourEyes reads the deployment's operator-identity hardening.
//
// It reads the same environment the two switches already read, rather than taking them as parameters,
// because a parameter is a chance for a caller to pass what it wishes were true. Both switches are
// bootstrap-scoped, so this cannot change under a running process.
func AssessFourEyes() FourEyesAssurance {
	var gaps []string
	if !strictOperatorRoles() {
		gaps = append(gaps, "OPENSHIELD_OPERATOR_ROLES_STRICT=0 (an identity with no server-side role "+
			"falls back to its certificate, so two operator certificates are two operators)")
	}
	if !requireBoundOperatorTokens() {
		gaps = append(gaps, "OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP=0 (an operator token that is not "+
			"sender-constrained is accepted, so two stolen tokens are two operators)")
	}
	if len(gaps) == 0 {
		return FourEyesAssurance{Level: AssuranceStrong}
	}
	return FourEyesAssurance{Level: AssuranceWeak, Gaps: gaps}
}

// RequireStrongFourEyes reports whether a weak deployment must REFUSE to resolve approvals rather than
// record them as weak.
//
// Default off, and this is the one place that decision is worth defending rather than apologising for.
// Defaulting it ON would make an upgrade silently break every existing four-eyes flow — case closure,
// fleet-control publication, high-impact response intents — on deployments that are running exactly as
// documented, and it would do so at the moment an operator is trying to approve something. That is a
// worse outcome than a recorded weak approval, because a recorded weak approval is VISIBLE and this
// would look like the feature being broken.
//
// What makes the default acceptable, and did not exist before, is that the weakness is now stated at
// startup and stamped on every row. Off means "recorded honestly", not "unmentioned".
func RequireStrongFourEyes() bool {
	return strings.TrimSpace(os.Getenv("OPENSHIELD_FOUR_EYES_REQUIRE_STRONG")) == "1"
}

// FourEyesStartupNotice is what a binary logs about its own two-person control, once, at startup.
//
// Returned rather than logged here so the caller uses its own logger, and so the text is testable — the
// property being asserted is that a weak deployment SAYS SO, which a test cannot check on a log line
// this package writes into a logger it invented.
func FourEyesStartupNotice(a FourEyesAssurance) string {
	if a.Strong() {
		return "four-eyes assurance STRONG — operator identities are resolved server-side and operator " +
			"tokens are sender-constrained, so two approvals are two people"
	}
	msg := "four-eyes assurance WEAK — approvals will be RECORDED as weak. A two-person control is " +
		"exactly as strong as this deployment's ability to tell two operators apart, and right now: " +
		strings.Join(a.Gaps, "; ")
	if RequireStrongFourEyes() {
		return msg + ". OPENSHIELD_FOUR_EYES_REQUIRE_STRONG=1 is set, so approvals will be REFUSED " +
			"until both are hardened"
	}
	return msg + ". Set OPENSHIELD_FOUR_EYES_REQUIRE_STRONG=1 to refuse approvals instead of recording " +
		"them as weak"
}
