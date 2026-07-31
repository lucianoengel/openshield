package gateway

import (
	"errors"
	"strconv"
)

// FIREWALL PLUMBING FOR THE INLINE QUIC PLANE (NIPS-12).
//
// A mangle PREROUTING TPROXY rule for UDP/443 plus the mark-based routing it needs, mirroring the TCP
// plane's plumbing exactly (tproxyrules.go) because it is the same mechanism for the same reason.
//
// IT IS NOT A NAT REDIRECT, AND THAT WAS LEARNED THE HARD WAY. A nat OUTPUT REDIRECT is what dnsredirect
// uses for :53 and it looked like the obvious model here, but IP_RECVORIGDSTADDR on a locally-generated
// REDIRECTed datagram reports the address AFTER the rewrite. A resolver does not care — a DNS query says
// what it is asking for — but a QUIC flow's destination is exactly what is lost, so the plane recovered
// its own listener address, forwarded every flow to itself, and looped until the flow table capped out.
// Measured on the VM: the redirect rule matched one packet and the plane decided 4097 times.
//
// TPROXY does not rewrite anything. It diverts the packet to a transparent socket with the original
// destination intact, which is the one fact this plane needs. It also means the plane's own forward — a
// locally-generated packet, and OUTPUT is not PREROUTING — is never caught, so there is no loop to break
// and no firewall mark to keep out of its own way.

// errQUICUnsupported keeps the tree cross-compiling. The plane depends on TPROXY, on IP_TRANSPARENT and on
// IP_RECVORIGDSTADDR, none of which exist off Linux — and a stub that silently listened would report an
// inline plane that decides nothing.
var errQUICUnsupported = errors.New("gateway: the inline QUIC plane is linux-only")

// quicDPort is the only UDP port QUIC is diverted from.
const quicDPort = "443"

// quicTProxyRuleSpec is the mangle PREROUTING rule body, shared by add and delete so teardown matches the
// rule exactly and never disturbs an operator's own PREROUTING entries.
//
// `! -i lo` is not decoration: a gateway must never divert its own loopback traffic, which would include
// the plane's forward whenever a destination happens to be local — the loop, reintroduced.
//
// It is a SEPARATE rule from the TCP plane's rather than a protocol parameter on it, so enabling QUIC
// cannot change the behaviour of the TCP path that is already deployed.
func quicTProxyRuleSpec(listenPort, mark int) []string {
	return []string{"-t", "mangle", "PREROUTING", "!", "-i", "lo", "-p", "udp", "--dport", quicDPort,
		"-j", "TPROXY", "--on-port", strconv.Itoa(listenPort), "--tproxy-mark", strconv.Itoa(mark)}
}

// quicInstallArgs builds the install commands: the routing sequence (a fwmark rule and a divert route in a
// DEDICATED table, so the broad "everything is local" route is reachable only by mark-tagged packets) and
// the mangle rule itself.
func quicInstallArgs(listenPort, mark, table int) (ip [][]string, ipt [][]string) {
	m, tbl := strconv.Itoa(mark), strconv.Itoa(table)
	ip = [][]string{
		{"rule", "add", "fwmark", m, "lookup", tbl},
		{"route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", tbl},
	}
	spec := quicTProxyRuleSpec(listenPort, mark)
	ipt = [][]string{append([]string{spec[0], spec[1], "-A"}, spec[2:]...)}
	return ip, ipt
}

// quicRemoveArgs builds the idempotent teardown: delete the exact rule, drop the fwmark rule, flush the
// dedicated table. It targets ONLY what this plane added.
//
// Teardown matters more here than it looks. A TPROXY rule that outlives its listener diverts the host's
// entire UDP/443 to a socket that no longer exists — a silent, total QUIC outage with no obvious cause.
func quicRemoveArgs(listenPort, mark, table int) (ip [][]string, ipt [][]string) {
	m, tbl := strconv.Itoa(mark), strconv.Itoa(table)
	spec := quicTProxyRuleSpec(listenPort, mark)
	ipt = [][]string{append([]string{spec[0], spec[1], "-D"}, spec[2:]...)}
	ip = [][]string{
		{"rule", "del", "fwmark", m, "lookup", tbl},
		{"route", "flush", "table", tbl},
	}
	return ip, ipt
}
