//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

// SEC-D, through the real binary: a deployment whose four-eyes is one credential must SAY SO, unasked,
// every boot.
//
// The unit tests pin the assessment and the recorded assurance. What only the binary can show is that
// the sentence actually reaches an operator — the whole defect was that a two-person control said
// nothing about the two shipped defaults that decide what an identity string is worth, so a test that
// asserts a function's return value and never checks that anything prints it would be reproducing the
// shape of the bug at one remove.
func TestTheServerStatesWhatItsFourEyesIsWorth(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)

	t.Run("unhardened says so and names both switches", func(t *testing.T) {
		srv := Start(t, "openshield-server", []string{
			"OPENSHIELD_DSN=" + stack.DSN,
			"OPENSHIELD_NATS_URL=" + stack.NATSURL,
			// The shipped defaults, set explicitly so this scenario states what it is testing rather
			// than depending on them staying the defaults.
			"OPENSHIELD_OPERATOR_ROLES_STRICT=0",
			"OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP=0",
		})
		srv.WaitForOutput("four-eyes assurance WEAK", 90*time.Second)

		out := srv.Output()
		for _, want := range []string{
			"OPENSHIELD_OPERATOR_ROLES_STRICT",
			"OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP",
			"OPENSHIELD_FOUR_EYES_REQUIRE_STRONG",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the startup notice does not mention %s — an operator told their identity model "+
					"is weak, without being told which knob to turn, acknowledges the message and leaves "+
					"it alone\n%s", want, out)
			}
		}
	})

	t.Run("hardened confirms", func(t *testing.T) {
		srv := Start(t, "openshield-server", []string{
			"OPENSHIELD_DSN=" + stack.DSNFor(t, "hardened"),
			"OPENSHIELD_NATS_URL=" + stack.NATSURL,
			"OPENSHIELD_OPERATOR_ROLES_STRICT=1",
			"OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP=1",
		})
		// A message that appears only on failure cannot be used to verify success, so an operator who has
		// done the migration gets a line confirming it counted.
		srv.WaitForOutput("four-eyes assurance STRONG", 90*time.Second)
		if contains(srv.Output(), "assurance WEAK") {
			t.Errorf("a hardened deployment was still reported weak\n%s", srv.Output())
		}
	})
}
