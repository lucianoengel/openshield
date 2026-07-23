package dnsredirect

import (
	"strings"
	"testing"
)

// flatten joins a command sequence into one searchable string per command.
func flatten(seq [][]string) string {
	var b strings.Builder
	for _, cmd := range seq {
		b.WriteString(strings.Join(cmd, " "))
		b.WriteString("\n")
	}
	return b.String()
}

// TestIptablesRuleCarriesRedirectAndMarkExemption: the install rules must redirect UDP :53 to the resolver
// port AND exempt the resolver's own mark (the loop-break). Without exempt the tokens must be gone — the
// mutation the unit test catches (6.2).
func TestIptablesRuleCarriesRedirectAndMarkExemption(t *testing.T) {
	got := flatten(iptablesInstallArgs(8053, 0x1d5, true))
	for _, want := range []string{"--dport 53", "REDIRECT", "--to-ports 8053", "! --mark 0x1d5"} {
		if !strings.Contains(got, want) {
			t.Fatalf("iptables install rules missing %q:\n%s", want, got)
		}
	}
	// exempt=false drops the loop-break exemption (the source-level mutation shape).
	if strings.Contains(flatten(iptablesInstallArgs(8053, 0x1d5, false)), "--mark") {
		t.Fatalf("non-exempt rule must NOT carry a mark exemption")
	}
}

// TestNftRuleCarriesRedirectAndMarkExemption mirrors the above for the nft backend.
func TestNftRuleCarriesRedirectAndMarkExemption(t *testing.T) {
	got := flatten(nftInstallArgs(8053, 0x1d5, true))
	for _, want := range []string{"udp dport 53", "redirect to :8053", "mark != 0x1d5"} {
		if !strings.Contains(got, want) {
			t.Fatalf("nft install rule missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(flatten(nftInstallArgs(8053, 0x1d5, false)), "mark !=") {
		t.Fatalf("non-exempt nft rule must NOT carry a mark exemption")
	}
}

// TestRemoveIsInverseTeardown: Remove targets exactly the dedicated chain/table it created, so teardown
// never touches unrelated operator rules.
func TestRemoveIsInverseTeardown(t *testing.T) {
	ipt := flatten(iptablesRemoveArgs())
	if !strings.Contains(ipt, iptChain) || !strings.Contains(ipt, "-X "+iptChain) {
		t.Fatalf("iptables remove must flush+delete the dedicated chain %q:\n%s", iptChain, ipt)
	}
	if strings.Contains(ipt, "-F OUTPUT") || strings.Contains(ipt, "-X OUTPUT") {
		t.Fatalf("remove must NOT flush/delete the OUTPUT chain (operator rules):\n%s", ipt)
	}
	nft := flatten(nftRemoveArgs())
	if !strings.Contains(nft, "delete table ip "+nftTable) {
		t.Fatalf("nft remove must delete only the dedicated table:\n%s", nft)
	}
}

// TestUnsupportedErrorMessage: the off-linux stub returns a clear linux-only error.
func TestUnsupportedErrorMessage(t *testing.T) {
	if !strings.Contains(errUnsupported.Error(), "linux-only") {
		t.Fatalf("errUnsupported = %q, want it to explain linux-only", errUnsupported.Error())
	}
}
