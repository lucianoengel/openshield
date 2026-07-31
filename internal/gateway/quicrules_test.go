package gateway

import (
	"strings"
	"testing"
)

// flattenQUIC renders an argv sequence as one searchable string.
func flattenQUIC(seq [][]string) string {
	var b strings.Builder
	for _, args := range seq {
		b.WriteString(strings.Join(args, " "))
		b.WriteString("\n")
	}
	return b.String()
}

// THE DIVERT IS TPROXY IN PREROUTING, NOT A NAT REDIRECT, and the difference is the whole feature.
//
// The first working version of this plane used a nat OUTPUT REDIRECT, copied from the :53 redirect next
// door. IP_RECVORIGDSTADDR then reported the destination AFTER the rewrite, so the plane recovered its own
// listener address and forwarded every flow to itself — measured on the VM as one matched packet and 4097
// decisions. TPROXY does not rewrite, which is why the destination survives.
func TestTheQUICDivertUsesTProxyRatherThanNAT(t *testing.T) {
	_, ipt := quicInstallArgs(40443, 0x1d7, 211)
	got := flattenQUIC(ipt)
	for _, want := range []string{"-t mangle", "PREROUTING", "-p udp", "--dport 443", "-j TPROXY",
		"--on-port 40443"} {
		if !strings.Contains(got, want) {
			t.Errorf("the divert rule is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "REDIRECT") || strings.Contains(got, "-t nat") {
		t.Errorf("the divert is a nat REDIRECT — the original destination will not survive it, and the "+
			"plane will forward every flow to its own listener:\n%s", got)
	}
}

// A GATEWAY MUST NEVER DIVERT ITS OWN LOOPBACK TRAFFIC.
//
// The plane's forward is locally generated, so PREROUTING does not see it — except on loopback, where a
// rule without this exclusion would catch the plane's own dial to a local destination and hand it straight
// back. That is the loop, reintroduced by omission.
func TestTheDivertExcludesLoopback(t *testing.T) {
	_, ipt := quicInstallArgs(40443, 0x1d7, 211)
	if got := flattenQUIC(ipt); !strings.Contains(got, "! -i lo") {
		t.Fatalf("the divert rule does not exclude loopback:\n%s", got)
	}
}

// THE DIVERT NEEDS ROUTING, and it is confined to a dedicated table.
//
// TPROXY only delivers to a local socket if policy routing sends mark-tagged packets to a table with a
// local route. That route says "every address is local", which is why it lives in a table nothing else
// consults rather than in the main one.
func TestTheDivertsRoutingIsConfinedToItsOwnTable(t *testing.T) {
	ip, _ := quicInstallArgs(40443, 0x1d7, 211)
	got := flattenQUIC(ip)
	for _, want := range []string{"rule add fwmark 471 lookup 211", "route add local 0.0.0.0/0",
		"table 211"} {
		if !strings.Contains(got, want) {
			t.Errorf("the routing setup is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "table main") {
		t.Errorf("the divert installs a broad local route into the MAIN routing table, which would make "+
			"every address local for all traffic on this host:\n%s", got)
	}
}

// TEARDOWN MATCHES THE RULE EXACTLY, so it removes what was added and nothing else.
//
// A TPROXY rule that outlives its listener diverts the host's entire UDP/443 to a socket that no longer
// exists: a silent, total QUIC outage with no obvious cause. Flushing PREROUTING would fix that by
// destroying an operator's own rules, which is worse.
func TestTeardownMatchesTheInstalledRuleExactly(t *testing.T) {
	_, addIpt := quicInstallArgs(40443, 0x1d7, 211)
	_, delIpt := quicRemoveArgs(40443, 0x1d7, 211)
	add, del := flattenQUIC(addIpt), flattenQUIC(delIpt)

	if strings.Replace(add, " -A ", " -D ", 1) != del {
		t.Fatalf("teardown is not the exact inverse of install, so it will leave the rule behind:\nadd: "+
			"%s\ndel: %s", add, del)
	}
	if strings.Contains(del, "-F") || strings.Contains(del, "--flush") {
		t.Fatalf("teardown FLUSHES a chain it does not own:\n%s", del)
	}
	ip, _ := quicRemoveArgs(40443, 0x1d7, 211)
	if got := flattenQUIC(ip); !strings.Contains(got, "route flush table 211") {
		t.Errorf("teardown does not flush the dedicated routing table:\n%s", got)
	}
}
