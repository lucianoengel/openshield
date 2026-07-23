package gateway

import (
	"errors"
	"strconv"
)

// This file installs the TPROXY plumbing (mark-based routing + a mangle TPROXY rule) that redirects
// forwarded TCP flows into the transparent inline listener (ListenTransparent), so the NIPS-1 inline plane
// is deployable without hand-crafted out-of-band firewall config (D234 taught OpenShield to own the DNS
// redirect; this is the same for TPROXY). The blast-radius part (a broad "everything is local" divert
// route) is confined to a DEDICATED routing table reached only by mark-tagged packets, and the mangle
// TPROXY rules are deleted by exact spec on teardown so operator PREROUTING rules are never disturbed.
//
// The TPROXY target is placed DIRECTLY in the mangle PREROUTING chain (not a jumped sub-chain): xt_TPROXY
// only diverts a packet in the PREROUTING hook, and delivery is unreliable from a user-defined sub-chain —
// proven on the VM. Teardown deletes each exact rule (`-D`), so it never touches unrelated PREROUTING rules.

// errTProxyUnsupported is returned off linux.
var errTProxyUnsupported = errors.New("gateway: self-installing TPROXY rules are linux-only")

// tproxyRuleSpec is the per-dport mangle PREROUTING TPROXY rule body (shared by add/delete so teardown
// matches exactly). It excludes the loopback interface (`! -i lo`): a gateway must never TPROXY its own
// loopback traffic — including the transparent server's own upstream dial when the destination is local —
// which would loop the dial straight back into the listener and wedge the flow.
func tproxyRuleSpec(dport, listenPort, mark int) []string {
	return []string{"-t", "mangle", "PREROUTING", "!", "-i", "lo", "-p", "tcp", "--dport", strconv.Itoa(dport),
		"-j", "TPROXY", "--on-port", strconv.Itoa(listenPort), "--tproxy-mark", strconv.Itoa(mark)}
}

// tproxyInstallArgs builds the install commands: the `ip` routing sequence (a fwmark rule + a divert route
// in a dedicated table) and the `iptables` mangle sequence (a TPROXY rule appended to PREROUTING per
// destination port).
func tproxyInstallArgs(listenPort int, dports []int, mark, table int) (ip [][]string, ipt [][]string) {
	m, tbl := strconv.Itoa(mark), strconv.Itoa(table)
	ip = [][]string{
		{"rule", "add", "fwmark", m, "lookup", tbl},
		{"route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", tbl},
	}
	for _, d := range dports {
		spec := tproxyRuleSpec(d, listenPort, mark)
		ipt = append(ipt, append([]string{spec[0], spec[1], "-A"}, spec[2:]...))
	}
	return ip, ipt
}

// tproxyRemoveArgs builds the idempotent teardown (each ignores "not found"): delete each exact TPROXY
// PREROUTING rule, delete the fwmark rule, and flush the dedicated routing table. It targets ONLY the exact
// rules OpenShield added and its own dedicated table — never PREROUTING as a whole or the main table.
func tproxyRemoveArgs(listenPort int, dports []int, mark, table int) (ip [][]string, ipt [][]string) {
	m, tbl := strconv.Itoa(mark), strconv.Itoa(table)
	for _, d := range dports {
		spec := tproxyRuleSpec(d, listenPort, mark)
		ipt = append(ipt, append([]string{spec[0], spec[1], "-D"}, spec[2:]...))
	}
	ip = [][]string{
		{"rule", "del", "fwmark", m, "lookup", tbl},
		{"route", "flush", "table", tbl},
	}
	return ip, ipt
}
