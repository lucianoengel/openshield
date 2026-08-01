package posture_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/posture"
	"google.golang.org/protobuf/proto"
)

// unwrap pulls the PostureUpdate back out of a signed report.
func unwrap(t *testing.T, data []byte) *corev1.PostureUpdate {
	t.Helper()
	var su corev1.SignedUpdate
	if err := proto.Unmarshal(data, &su); err != nil {
		t.Fatal(err)
	}
	var pu corev1.PostureUpdate
	if err := proto.Unmarshal(su.GetPayload(), &pu); err != nil {
		t.Fatal(err)
	}
	return &pu
}

func signed(t *testing.T, r posture.Report) *corev1.PostureUpdate {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := posture.Build("subj", r, priv)
	if err != nil {
		t.Fatal(err)
	}
	return unwrap(t, data)
}

// BINARY INTEGRITY TRAVELS WITH THE POSTURE REPORT.
//
// Without this the answer stays a log line on the host that was compromised. Carried in posture, it
// becomes a fleet-wide fact and — because the gateway decides access on posture — something the
// compromised endpoint does not get a vote on.
//
// Mutation (drop the field from Build): the gateway always sees UNCHECKED, every integrity policy denies
// everything, and an operator concludes the feature does not work → FAIL.
func TestBinaryIntegrityIsCarriedInTheSignedReport(t *testing.T) {
	for _, want := range []core.BinaryIntegrity{
		core.BinariesUnchecked, core.BinariesVerified, core.BinariesMismatch,
	} {
		pu := signed(t, posture.Report{Binaries: want})
		if got := core.BinaryIntegrity(pu.GetBinaryIntegrity()); got != want {
			t.Errorf("reported %v, want %v — the state the endpoint computed is not the state the "+
				"gateway will act on", got, want)
		}
	}
}

// DETECT NEVER CLAIMS AN INTEGRITY IT DID NOT VERIFY.
//
// Answering the question needs the operator's public key, which posture.Detect does not have. Returning
// VERIFIED by default would mean every endpoint on earth asserts an integrity nobody checked — the
// failure this package's own doc comment warns against for disk encryption, in a field where it would be
// worse.
func TestDetectReportsUncheckedRatherThanAssumingVerified(t *testing.T) {
	if got := posture.Detect().Binaries; got != core.BinariesUnchecked {
		t.Fatalf("Detect reported %v without a key to verify against. A posture detector that asserts "+
			"an integrity it never checked is worse than one that says nothing", got)
	}
}

// UNCHECKED IS THE ZERO VALUE, so a policy requiring VERIFIED fails closed on a device that never
// answered — the same discipline as HasPosture.
func TestTheZeroValueIsUnchecked(t *testing.T) {
	var b core.BinaryIntegrity
	if b != core.BinariesUnchecked {
		t.Fatal("the zero value is not UNCHECKED, so an endpoint that reported nothing would arrive at " +
			"the gateway looking like one that passed")
	}
	if core.BinariesUnchecked.String() == core.BinariesVerified.String() {
		t.Fatal("UNCHECKED and VERIFIED render identically, so a policy comparing the name cannot tell " +
			"a device that passed from one that was never asked")
	}
	// And the names are what a policy compares, so they must be stable and distinct.
	for state, want := range map[core.BinaryIntegrity]string{
		core.BinariesUnchecked: "UNCHECKED",
		core.BinariesVerified:  "VERIFIED",
		core.BinariesMismatch:  "MISMATCH",
	} {
		if got := state.String(); got != want {
			t.Errorf("%d renders as %q, want %q — policies are written against these names", state, got, want)
		}
	}
}
