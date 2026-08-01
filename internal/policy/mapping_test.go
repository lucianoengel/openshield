package policy_test

import (
	"context"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// A ZT POLICY CAN REFUSE AN ENDPOINT RUNNING BINARIES NOBODY PUBLISHED.
//
// This is what the whole chain is for. Self-verification on the host is bypassable by whoever owns the
// host; the decision made HERE is not, because it happens at the gateway. The endpoint reports, the
// gateway stores, and access is refused to a device whose files do not match the release they claim.
//
// The three states are exercised together on purpose: separately, "MISMATCH is denied" passes for a
// policy that denies everything, and "VERIFIED is allowed" passes for one that allows everything. The
// claim is that it DISTINGUISHES them — including UNCHECKED, which must not pass, or an endpoint that
// simply never answered would satisfy a control that requires an answer.
func TestAPolicyCanRequireVerifiedBinaries(t *testing.T) {
	pol, err := policy.New(context.Background(), "integrity", "1", `package openshield
import rego.v1
verified if { input.context.device_posture.binary_integrity == "VERIFIED" }
decision := {"action":"ALLOW","reason":"binaries match the published release","confidence":1.0} if { verified }
decision := {"action":"BLOCK","reason":"this host is not running the published binaries","confidence":1.0} if { not verified }`)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		state core.BinaryIntegrity
		allow bool
	}{
		{core.BinariesVerified, true},
		{core.BinariesMismatch, false},
		{core.BinariesUnchecked, false},
	} {
		st := &core.State{
			Event:   &corev1.Event{Kind: corev1.EventKind_EVENT_KIND_HTTP_REQUEST},
			Context: &core.Context{DevicePosture: core.DevicePosture{HasPosture: true, Binaries: tc.state}},
		}
		out, rerr := pol.Run(context.Background(), st)
		if rerr != nil {
			t.Fatalf("%v: %v", tc.state, rerr)
		}
		if out.Kind != core.OutcomeDecided || out.Decision == nil {
			t.Fatalf("%v: no decision (%v)", tc.state, out.Kind)
		}
		allowed := out.Decision.GetAction() == corev1.Action_ACTION_ALLOW
		if allowed != tc.allow {
			t.Errorf("%v: allowed=%v, want %v. An endpoint reporting %v must %s — otherwise the "+
				"integrity signal reaches policy and changes nothing", tc.state, allowed, tc.allow,
				tc.state, map[bool]string{true: "be admitted", false: "be refused"}[tc.allow])
		}
	}
}
