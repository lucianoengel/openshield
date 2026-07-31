// Package bypassguard stops an endpoint reaching protected internal services EXCEPT through the ZTNA
// gateway, and counts the attempts that were stopped (ZT-10).
//
// THE GAP IT CLOSES, STATED PLAINLY. The access broker authenticates a device and a user, checks posture
// and risk, and admits or refuses per service. None of that binds if a client can simply open a socket to
// the database's address directly. A gate you can walk around is a suggestion, and every property the
// broker enforces — dual credential, posture, continuous verification — is enforced only on people who
// choose to use it.
//
// WHAT THIS IS AND IS NOT. This is the ENDPOINT half: a firewall rule set on the client that rejects
// traffic to the protected ranges unless it is going to the gateway. The other half — the protected
// network accepting connections only from the gateway — is where enforcement really binds, and it lives
// in the network, not in this product. What the endpoint half adds is cost and, more importantly,
// VISIBILITY: a bypass attempt becomes a counted, reportable event rather than a connection nobody sees.
//
// AND IT IS NOT EFFECTIVE AGAINST ROOT. A user with root on their own machine deletes these rules. That
// is the threat model this project has stated since D16 and it is not weakened here: against a careless
// or casually curious insider this closes the path; against a determined one with root it raises the bar
// and leaves a record. Anyone reading "prevents bypass" as "cannot be bypassed" is reading a claim this
// package does not make.
//
// REJECT, NOT DROP. A dropped packet looks like a broken network: the user waits for a timeout, retries,
// and files a ticket. An ICMP administratively-prohibited says immediately that a policy refused this,
// which is both true and the fastest route to the user going through the gateway instead. Silence would
// be indistinguishable from an outage — the failure mode this whole product refuses.
package bypassguard

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// errUnsupported is returned when the guard cannot be installed on this platform.
var errUnsupported = errors.New("bypassguard: the endpoint bypass guard is linux-only")

// ErrNoGateway is returned when no gateway address is given.
//
// It is an error rather than a default because the failure is silent and total: a guard with no exemption
// rejects traffic to the gateway along with everything else, so the endpoint loses access to the
// protected services entirely. That is not enforcement, it is an outage — and it would arrive looking
// exactly like the feature working.
var ErrNoGateway = errors.New("bypassguard: a gateway address is required — a guard that does not exempt " +
	"the gateway blocks the only permitted path, which is an outage rather than enforcement")

// ErrNoProtected is returned when nothing is protected: a guard that guards nothing installs rules,
// reports success and changes no behaviour, which is worse than not running because it reads as covered.
var ErrNoProtected = errors.New("bypassguard: no protected ranges — a guard that guards nothing still " +
	"reports success, which reads as coverage")

const chain = "OPENSHIELD_ZTBYPASS" // dedicated chain, so teardown never touches operator rules

// Config is what the guard enforces.
type Config struct {
	// Gateway is the ZTNA gateway's address — the one permitted path. Required.
	Gateway string
	// Protected are the addresses or CIDRs that may be reached ONLY through the gateway.
	Protected []string
	// AlsoAllow are further exempt destinations. THE CONTROL PLANE BELONGS HERE whenever it sits inside
	// a protected range: the agent's own telemetry would otherwise be rejected by this guard, the agent
	// would go silent, and a silent agent is exactly the signal a compromised endpoint produces (D50).
	// The guard would be manufacturing its own alarm.
	AlsoAllow []string
}

// family splits a destination into the v4 and v6 worlds, because they are enforced by different binaries
// and a rule installed in one does nothing in the other.
type family int

const (
	fam4 family = iota
	fam6
)

// classify resolves a destination to its address family.
//
// An unparseable entry is an ERROR, never skipped. A silently-skipped protected range is a hole in the
// guard that reports success — the shape D31 exists to forbid — and it would be a hole in exactly the
// range somebody typed carefully enough to get slightly wrong.
func classify(dest string) (family, error) {
	d := strings.TrimSpace(dest)
	if d == "" {
		return fam4, fmt.Errorf("bypassguard: empty destination")
	}
	if ip, _, err := net.ParseCIDR(d); err == nil {
		if ip.To4() != nil {
			return fam4, nil
		}
		return fam6, nil
	}
	if ip := net.ParseIP(d); ip != nil {
		if ip.To4() != nil {
			return fam4, nil
		}
		return fam6, nil
	}
	return fam4, fmt.Errorf("bypassguard: %q is not an IP address or CIDR — a destination that cannot be "+
		"resolved to a firewall rule would be silently unguarded", dest)
}

// split partitions a config into per-family destination lists, failing on anything unparseable.
func (c Config) split() (v4, v6 plan, err error) {
	if strings.TrimSpace(c.Gateway) == "" {
		return plan{}, plan{}, ErrNoGateway
	}
	if len(c.Protected) == 0 {
		return plan{}, plan{}, ErrNoProtected
	}
	add := func(dest string, toExempt bool) error {
		fam, ferr := classify(dest)
		if ferr != nil {
			return ferr
		}
		p := &v4
		if fam == fam6 {
			p = &v6
		}
		if toExempt {
			p.exempt = append(p.exempt, strings.TrimSpace(dest))
		} else {
			p.protected = append(p.protected, strings.TrimSpace(dest))
		}
		return nil
	}
	if err := add(c.Gateway, true); err != nil {
		return plan{}, plan{}, fmt.Errorf("gateway: %w", err)
	}
	for _, a := range c.AlsoAllow {
		if strings.TrimSpace(a) == "" {
			continue
		}
		if err := add(a, true); err != nil {
			return plan{}, plan{}, err
		}
	}
	for _, p := range c.Protected {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if err := add(p, false); err != nil {
			return plan{}, plan{}, err
		}
	}
	return v4, v6, nil
}

// plan is one address family's rule set.
type plan struct {
	exempt    []string
	protected []string
}

// empty reports whether this family has anything to guard.
func (p plan) empty() bool { return len(p.protected) == 0 }

// removeArgs is the idempotent teardown: unhook the OUTPUT jump, flush and delete the chain. Each is
// run best-effort, so a re-install after an unclean shutdown never fails on a partially-clean state.
func removeArgs() [][]string {
	return [][]string{
		{"-D", "OUTPUT", "-j", chain},
		{"-F", chain},
		{"-X", chain},
	}
}

// scaffoldArgs creates the chain (best-effort — "exists" is benign after the teardown flush).
func scaffoldArgs() [][]string { return [][]string{{"-N", chain}} }

// installArgs builds the FATAL rules, in the order that makes them correct.
//
// THE EXEMPTIONS COME FIRST, and the ordering is load-bearing rather than tidy. The gateway usually sits
// INSIDE a protected range — that is the normal deployment, a gateway fronting the subnet it guards — so
// an exemption appended after the rejects never matches, and the guard blocks the one path it exists to
// preserve. The endpoint then cannot reach the protected services at all, through the gateway or
// otherwise, and the failure looks like the feature working.
func installArgs(p plan, rejectWith string) [][]string {
	var out [][]string
	for _, e := range p.exempt {
		out = append(out, []string{"-A", chain, "-d", e, "-j", "RETURN"})
	}
	for _, d := range p.protected {
		out = append(out, []string{"-A", chain, "-d", d, "-j", "REJECT", "--reject-with", rejectWith})
	}
	// The hook goes in LAST, so the chain is fully populated before any packet can traverse it. Hooking
	// first would leave a window in which OUTPUT jumps into an empty chain and every protected
	// destination is reachable — brief, but exactly during startup, which is when a script that races
	// the guard would run.
	out = append(out, []string{"-A", "OUTPUT", "-j", chain})
	return out
}

// listArgs reads the chain with its packet counters.
func listArgs() []string { return []string{"-L", chain, "-n", "-v", "-x"} }

// ParseAttempts sums the packet counts of the REJECT rules in `iptables -L <chain> -n -v -x` output —
// how many times this endpoint tried to reach a protected service directly.
//
// THAT NUMBER IS THE DETECTION HALF of this feature and is worth more than the blocking. A rejected
// connection to the payroll database from a laptop is a person or a process trying to go around the
// broker, which is a finding whether or not the attempt succeeded.
//
// A malformed line is an ERROR, never a zero. Reporting zero on a parse failure would say "no bypass
// attempts" when the truth is "we do not know", and those are opposite answers to the only question this
// counter is asked.
func ParseAttempts(out string) (int64, error) {
	var total int64
	var sawChain, sawRule bool
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == "Chain" {
			sawChain = true
			continue
		}
		if f[0] == "pkts" {
			continue // the header row
		}
		if len(f) < 3 || f[2] != "REJECT" {
			continue
		}
		n, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("bypassguard: unreadable packet count %q in %q: %w", f[0], line, err)
		}
		total += n
		sawRule = true
	}
	if !sawChain {
		return 0, fmt.Errorf("bypassguard: no %s chain in the firewall listing — the guard is not "+
			"installed, which is not the same as no attempts having been made", chain)
	}
	if !sawRule {
		// A chain with no REJECT rule guards nothing. Zero attempts against it is a true statement about
		// a guard that is not guarding, and reporting it as a clean result would be the lie.
		return 0, fmt.Errorf("bypassguard: the %s chain has no REJECT rule — nothing is being guarded", chain)
	}
	return total, nil
}
