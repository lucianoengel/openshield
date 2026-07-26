package clipboard_test

import (
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/clipboard"
)

// TestWaylandNeverClaimsDestinationAttribution: the asymmetry between display servers is a protocol fact,
// and reporting it wrongly would be the overclaim the project's review rounds exist to catch.
//
// Mutation: report destination attribution on the polled/Wayland backend → this FAILS.
func TestWaylandNeverClaimsDestinationAttribution(t *testing.T) {
	w := clipboard.PolledHelperCapabilities(clipboard.DisplayWayland)
	if w.DestinationAttribution {
		t.Error("the Wayland backend claims destination attribution — the data-control protocols never " +
			"identify the client receiving a paste; this is impossible, not merely unimplemented")
	}
	if w.Enforcement {
		t.Error("the polled backend claims enforcement; it can only read")
	}
	if w.SourceAttribution {
		t.Error("the polled backend claims source attribution; it cannot see the owner")
	}
	var mentionsProtocolLimit bool
	for _, l := range w.Limits {
		if strings.Contains(l, "CANNOT provide destination attribution") {
			mentionsProtocolLimit = true
		}
	}
	if !mentionsProtocolLimit {
		t.Error("the Wayland limits do not state the protocol-level impossibility an operator needs to know")
	}
}

// TestX11MediationClaimsTheFullSetAndItsLimits: X11 genuinely gives all four, and the limits that remain
// (clipboard managers, no INCR, text only, root) must be stated alongside.
func TestX11MediationClaimsTheFullSetAndItsLimits(t *testing.T) {
	c := clipboard.X11MediationCapabilities()
	if !c.Capture || !c.SourceAttribution || !c.DestinationAttribution || !c.Enforcement {
		t.Fatalf("X11 mediation should provide all four capabilities: %+v", c)
	}
	joined := strings.Join(c.Limits, " | ")
	for _, want := range []string{"clipboard manager", "INCR", "text targets only", "root"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the X11 limits omit %q — a capability list without its caveats is an overclaim", want)
		}
	}
	if !strings.Contains(c.Summary(), "destination-attribution=true") {
		t.Errorf("summary = %q, want it to state what was obtained", c.Summary())
	}
}
