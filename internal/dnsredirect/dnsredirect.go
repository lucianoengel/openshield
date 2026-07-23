// Package dnsredirect installs a transparent redirect of locally-originated UDP :53 traffic to the local
// DNS sinkhole resolver (NIPS-8 increment 2), so a client that is NOT configured to use the resolver is
// still subject to the sinkhole. It shells out to iptables (preferred) or nft, mirroring the TPROXY
// connector's subprocess model.
//
// The security-relevant core is the LOOP-BREAK. A rule that redirected every :53 packet would capture the
// resolver's OWN forward to the real upstream (also :53) and loop it straight back into the resolver,
// breaking all name resolution. The redirect therefore EXEMPTS packets carrying the resolver's firewall
// mark (SO_MARK, set by dnssink.Resolver.Mark): the resolver's forwarded queries escape the redirect and
// reach the real upstream. This is the standard transparent-DNS-proxy loop-break; both the mark and the
// nat rule need CAP_NET_ADMIN, so this is a root-only, VM-proven capability.
package dnsredirect

import (
	"errors"
	"fmt"
)

// errUnsupported is returned when the transparent redirect cannot be installed on this platform.
var errUnsupported = errors.New("dnsredirect: transparent DNS redirect is linux-only")

// Names of the dedicated firewall objects, so Remove is a clean single-target teardown that never touches
// unrelated operator rules.
const (
	iptChain = "OPENSHIELD_DNSREDIR"    // custom chain in the nat table (iptables backend)
	nftTable = "openshield_dnsredirect" // dedicated table (nft backend)
)

// markHex renders a firewall mark the way iptables/nft accept it.
func markHex(mark int) string { return fmt.Sprintf("0x%x", mark) }

// iptablesRemoveArgs is the idempotent teardown for the iptables backend: unhook the OUTPUT jump, flush and
// delete the custom chain. Each invocation ignores a "not found" error, so Remove (and the remove-then-add
// prefix of Install) never fails on a clean or partially-clean state.
func iptablesRemoveArgs() [][]string {
	return [][]string{
		{"-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptChain},
		{"-t", "nat", "-F", iptChain},
		{"-t", "nat", "-X", iptChain},
	}
}

// iptablesScaffoldArgs creates the custom chain (best-effort — a benign "chain exists" is fine after the
// teardown flush).
func iptablesScaffoldArgs() [][]string {
	return [][]string{{"-t", "nat", "-N", iptChain}}
}

// iptablesInstallArgs builds the fatal create rules for the iptables backend: the redirect rule and the
// OUTPUT jump into the custom chain. When exempt is true the redirect rule carries the mark-EXEMPTION
// (`-m mark ! --mark <mark>`) that breaks the resolver→upstream loop — omitting it (the mutation) makes the
// resolver redirect its own upstream query back into itself.
func iptablesInstallArgs(port, mark int, exempt bool) [][]string {
	rule := []string{"-t", "nat", "-A", iptChain, "-p", "udp", "--dport", "53"}
	if exempt {
		rule = append(rule, "-m", "mark", "!", "--mark", markHex(mark))
	}
	rule = append(rule, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", port))
	return [][]string{
		rule,
		{"-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptChain},
	}
}

// nftRemoveArgs tears down the dedicated nft table in one shot (ignoring "no such table").
func nftRemoveArgs() [][]string {
	return [][]string{{"delete", "table", "ip", nftTable}}
}

// nftScaffoldArgs creates the dedicated table + nat/output chain (best-effort).
func nftScaffoldArgs() [][]string {
	return [][]string{
		{"add", "table", "ip", nftTable},
		{"add", "chain", "ip", nftTable, "out", "{", "type", "nat", "hook", "output", "priority", "-100", ";", "}"},
	}
}

// nftInstallArgs builds the fatal redirect rule for the nft backend. exempt adds the `mark != <mark>`
// loop-break exemption.
func nftInstallArgs(port, mark int, exempt bool) [][]string {
	rule := []string{"add", "rule", "ip", nftTable, "out", "udp", "dport", "53"}
	if exempt {
		rule = append(rule, "mark", "!=", markHex(mark))
	}
	rule = append(rule, "redirect", "to", ":"+fmt.Sprintf("%d", port))
	return [][]string{rule}
}
