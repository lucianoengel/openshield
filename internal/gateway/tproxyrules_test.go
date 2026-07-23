package gateway

import (
	"strings"
	"testing"
)

func flattenArgs(seq [][]string) string {
	var b strings.Builder
	for _, cmd := range seq {
		b.WriteString(strings.Join(cmd, " "))
		b.WriteString("\n")
	}
	return b.String()
}

// TestTProxyInstallArgs: the routing half carries the fwmark rule + the divert route in the dedicated
// table; the iptables half carries a per-dport TPROXY rule (on-port + tproxy-mark) in the dedicated chain
// plus the PREROUTING jump.
func TestTProxyInstallArgs(t *testing.T) {
	ip, ipt := tproxyInstallArgs(9998, []int{80, 443}, 1, 100)
	ipStr, iptStr := flattenArgs(ip), flattenArgs(ipt)

	for _, want := range []string{"rule add fwmark 1 lookup 100", "route add local 0.0.0.0/0 dev lo table 100"} {
		if !strings.Contains(ipStr, want) {
			t.Fatalf("ip install args missing %q:\n%s", want, ipStr)
		}
	}
	for _, want := range []string{
		"-A PREROUTING ! -i lo -p tcp --dport 80 -j TPROXY --on-port 9998 --tproxy-mark 1",
		"-A PREROUTING ! -i lo -p tcp --dport 443 -j TPROXY --on-port 9998 --tproxy-mark 1",
	} {
		if !strings.Contains(iptStr, want) {
			t.Fatalf("iptables install args missing %q:\n%s", want, iptStr)
		}
	}
}

// TestTProxyRemoveIsInverseAndScoped: Remove deletes ONLY the exact rules it added + its dedicated table +
// fwmark rule — never flushes PREROUTING itself or the main routing table (which would wreck operator
// networking).
func TestTProxyRemoveIsInverseAndScoped(t *testing.T) {
	ip, ipt := tproxyRemoveArgs(9998, []int{80, 443}, 1, 100)
	ipStr, iptStr := flattenArgs(ip), flattenArgs(ipt)

	for _, want := range []string{
		"-D PREROUTING ! -i lo -p tcp --dport 80 -j TPROXY --on-port 9998 --tproxy-mark 1",
		"-D PREROUTING ! -i lo -p tcp --dport 443 -j TPROXY --on-port 9998 --tproxy-mark 1",
	} {
		if !strings.Contains(iptStr, want) {
			t.Fatalf("iptables remove args missing %q:\n%s", want, iptStr)
		}
	}
	if strings.Contains(iptStr, "-F PREROUTING") || strings.Contains(iptStr, "-X PREROUTING") {
		t.Fatalf("remove must NOT flush/delete PREROUTING itself:\n%s", iptStr)
	}
	if !strings.Contains(ipStr, "rule del fwmark 1 lookup 100") || !strings.Contains(ipStr, "route flush table 100") {
		t.Fatalf("ip remove must delete the fwmark rule and flush the dedicated table:\n%s", ipStr)
	}
	if strings.Contains(ipStr, "flush table main") || strings.Contains(ipStr, "route flush\n") {
		t.Fatalf("remove must NOT flush the main routing table:\n%s", ipStr)
	}
}

// TestTProxyUnsupportedMessage: the off-linux stub returns a clear linux-only error.
func TestTProxyUnsupportedMessage(t *testing.T) {
	if !strings.Contains(errTProxyUnsupported.Error(), "linux-only") {
		t.Fatalf("errTProxyUnsupported = %q, want linux-only", errTProxyUnsupported.Error())
	}
}
