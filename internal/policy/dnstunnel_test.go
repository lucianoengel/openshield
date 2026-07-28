package policy_test

import (
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/connectors/dns"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// NIPS-3: the DNS tunnelling signal reaching a decision.
//
// dns.TunnelScore was written, documented and unit-tested with NO CALLER — the connector minted DNS
// events and nothing ever scored the name. These tests are about the seam that was missing: the score
// reaching the policy input, and the policy turning it into an action.

func dnsEvent(t *testing.T, name string) *core.State {
	t.Helper()
	return &core.State{Event: dns.ToEvent("1", "10.0.0.7", dns.Query{Name: name, QType: 1})}
}

// TestATunnellingNameAlertsAndAnOrdinaryOneDoesNot.
//
// BOTH HALVES. "The tunnelling name alerted" is satisfied by a detector that alerts on everything, which
// is worse than one that alerts on nothing: an alert channel that has to be ignored.
func TestATunnellingNameAlertsAndAnOrdinaryOneDoesNot(t *testing.T) {
	st := mustDefault(t)

	// A long, high-entropy label — data encoded into a subdomain, which is what a tunnel looks like.
	const tunnelled = "m5zwc3lbnfxgkltdn5wq6ztbnrxxg5dbnzqxg4tfnvzwk3llom.exfil.example"
	d := decide(t, st, dnsEvent(t, tunnelled))
	if d.GetAction() != corev1.Action_ACTION_ALERT {
		t.Errorf("a tunnelling query name produced %v, want ALERT — the score reaches the policy input "+
			"and no rule acts on it (score=%.3f threshold=%.3f)",
			d.GetAction(), dns.TunnelScore(tunnelled), dns.TunnelThreshold())
	}

	// AND THE REASON MUST NOT CARRY THE NAME. In a DNS tunnel the exfiltrated data IS the name, so a
	// reason string quoting it would put the payload in the ledger — the disclosure the rule detects.
	if r := d.GetReason(); strings.Contains(r, "m5zwc3lbnfxgkltdn5wq6ztbnrxxg5dbnzqxg4tfnvzwk3llom") {
		t.Errorf("the decision reason contains the queried name: %q", r)
	}

	for _, ordinary := range []string{
		"www.example.com",
		"api.github.com",
		"login.microsoftonline.com",
	} {
		d := decide(t, st, dnsEvent(t, ordinary))
		if d.GetAction() == corev1.Action_ACTION_ALERT {
			t.Errorf("an ordinary name %q ALERTED (score=%.3f). A tunnelling detector that fires on "+
				"normal resolution is an alert channel operators learn to ignore",
				ordinary, dns.TunnelScore(ordinary))
		}
	}
}

// TestANonDnsEventCarriesNoTunnellingInput.
//
// Absence is information. A DNS input present with a zero score on a file event would tell a policy
// author that a query was assessed and found clean, when there was no query.
func TestANonDnsEventCarriesNoTunnellingInput(t *testing.T) {
	st := mustDefault(t)
	// An HTTP flow — a network event that is NOT a DNS query, which is the case a kind check must
	// separate. A file event would pass even if the guard were on GetNetwork() rather than on the kind.
	ev := &corev1.Event{
		ConnectorId: "gateway", EventId: "http-1",
		Kind: corev1.EventKind_EVENT_KIND_NETWORK_FLOW,
		Target: &corev1.Event_Network{Network: &corev1.NetworkSubject{
			FlowId: "1", SrcIp: "10.0.0.7", DstPort: 443, Protocol: "tcp",
			// A host that WOULD score above the threshold if it were scored.
			SniHost: "m5zwc3lbnfxgkltdn5wq6ztbnrxxg5dbnzqxg4tfnvzwk3llom.exfil.example",
		}},
	}
	d := decide(t, st, &core.State{Event: ev})
	if d.GetAction() == corev1.Action_ACTION_ALERT {
		t.Error("a non-DNS network event alerted on the tunnelling rule. The score is being computed " +
			"for any host, so an HTTPS request to a long random hostname — a CDN, a pre-signed URL — " +
			"would alert as a DNS tunnel")
	}
}

// TestTheTunnelThresholdIsRespected: the comparison uses the configured value, not a constant.
func TestTheTunnelThresholdIsRespected(t *testing.T) {
	st := mustDefault(t)
	const name = "moderately-long-label-here.example.com"
	score := dns.TunnelScore(name)

	dns.SetTunnelThreshold(1.0) // unreachable
	defer dns.SetTunnelThreshold(dns.DefaultTunnelThreshold)
	d := decide(t, st, dnsEvent(t, name))
	if d.GetAction() == corev1.Action_ACTION_ALERT {
		t.Fatalf("a query scoring %.3f alerted against a threshold of 1.0 — the rule is comparing "+
			"against something other than the configured threshold", score)
	}

	// Below the score: it must now alert. Without this half, the assertion above is satisfied by a rule
	// that never fires at all.
	dns.SetTunnelThreshold(score / 2)
	d = decide(t, st, dnsEvent(t, name))
	if d.GetAction() != corev1.Action_ACTION_ALERT {
		t.Errorf("a query scoring %.3f did not alert against a threshold of %.3f", score, score/2)
	}
}
