package bypassguard

import (
	"errors"
	"strings"
	"testing"
)

// ZT-10 — ENDPOINT BYPASS GUARD.
//
// The access broker authenticates a device and a user, checks posture and risk, and admits or refuses per
// service. None of that binds if a client can open a socket to the database's address directly. A gate you
// can walk around is a suggestion, and every property the broker enforces is then enforced only on people
// who choose to use it.
//
// These tests are the rule BUILDER — no root, no kernel. The gated kernel test proves the rules actually
// reject; these prove they say what they must, in the order that makes them correct.

func argvString(argv [][]string) string {
	var b strings.Builder
	for _, a := range argv {
		b.WriteString(strings.Join(a, " "))
		b.WriteString("\n")
	}
	return b.String()
}

// THE EXEMPTION COMES BEFORE THE REJECTS, and the ordering is the whole feature.
//
// The gateway normally sits INSIDE a protected range — that is the ordinary deployment, a gateway fronting
// the subnet it guards. An exemption appended after the rejects never matches, so the guard blocks the one
// path it exists to preserve: the endpoint loses the protected services entirely, through the gateway or
// otherwise, and the outage looks exactly like the feature working.
//
// Mutation (emit the protected rejects before the exemptions): the gateway's RETURN lands after the
// REJECT covering it → FAIL.
func TestTheGatewayExemptionIsOrderedBeforeTheRejects(t *testing.T) {
	v4, _, err := Config{
		Gateway:   "10.0.0.1", // inside the protected range below — the normal case
		Protected: []string{"10.0.0.0/24"},
	}.split()
	if err != nil {
		t.Fatal(err)
	}
	got := argvString(installArgs(v4, "icmp-admin-prohibited"))

	ret := strings.Index(got, "-d 10.0.0.1 -j RETURN")
	rej := strings.Index(got, "-d 10.0.0.0/24 -j REJECT")
	if ret < 0 || rej < 0 {
		t.Fatalf("rules missing an exemption or a reject:\n%s", got)
	}
	if ret > rej {
		t.Fatalf("the gateway exemption is ordered AFTER the reject that covers it:\n%s\n"+
			"iptables takes the first match, so the exemption never fires and the endpoint cannot "+
			"reach the protected services at all — including through the gateway. That is an outage "+
			"wearing the feature's clothes", got)
	}
}

// THE OUTPUT HOOK GOES IN LAST.
//
// Hooking first leaves a window where OUTPUT jumps into an empty chain and every protected destination is
// reachable. Brief — and precisely during startup, which is when a script racing the guard would run.
//
// Mutation (prepend the hook): it lands before the rejects → FAIL.
func TestTheOutputHookIsInstalledLast(t *testing.T) {
	v4, _, err := Config{Gateway: "10.0.0.1", Protected: []string{"10.9.0.0/16"}}.split()
	if err != nil {
		t.Fatal(err)
	}
	argv := installArgs(v4, "icmp-admin-prohibited")
	last := argv[len(argv)-1]
	if strings.Join(last, " ") != "-A OUTPUT -j "+chain {
		t.Fatalf("the last rule is %q, want the OUTPUT hook — hooking before the chain is populated "+
			"leaves every protected destination reachable for a window, at startup, which is exactly "+
			"when something racing the guard would run", strings.Join(last, " "))
	}
}

// THE CONTROL PLANE CAN BE EXEMPTED, and this is not a convenience.
//
// If the control plane sits inside a protected range, the agent's own telemetry is rejected by this guard,
// the agent goes silent, and a silent agent is the exact signal a COMPROMISED endpoint produces (D50). The
// guard would be manufacturing its own alarm.
func TestAdditionalExemptionsAreHonoured(t *testing.T) {
	v4, _, err := Config{
		Gateway:   "10.0.0.1",
		Protected: []string{"10.0.0.0/8"},
		AlsoAllow: []string{"10.5.5.5"}, // the control plane, inside the protected range
	}.split()
	if err != nil {
		t.Fatal(err)
	}
	got := argvString(installArgs(v4, "icmp-admin-prohibited"))
	cp := strings.Index(got, "-d 10.5.5.5 -j RETURN")
	rej := strings.Index(got, "-d 10.0.0.0/8 -j REJECT")
	if cp < 0 || cp > rej {
		t.Fatalf("the control-plane exemption is missing or ordered after the reject:\n%s\n"+
			"the agent's own telemetry would be blocked, the agent would go silent, and a silent agent "+
			"is what a compromised endpoint looks like", got)
	}
}

// IPv6 IS A SEPARATE FIREWALL, AND A v6 PROTECTED RANGE MUST LAND IN IT.
//
// A rule installed with iptables does nothing to IPv6 traffic. An endpoint on a dual-stack network would
// route around a v4-only guard without trying — not as an attack, just by preferring AAAA.
//
// Mutation (put everything in the v4 plan): the v6 range appears in v4 and the v6 plan is empty → FAIL.
func TestProtectedRangesAreSplitByAddressFamily(t *testing.T) {
	v4, v6, err := Config{
		Gateway:   "10.0.0.1",
		Protected: []string{"10.0.0.0/24", "fd00:db8::/32"},
		AlsoAllow: []string{"fd00:db8::1"},
	}.split()
	if err != nil {
		t.Fatal(err)
	}
	if len(v4.protected) != 1 || v4.protected[0] != "10.0.0.0/24" {
		t.Errorf("v4 protected = %v, want just the v4 range", v4.protected)
	}
	if len(v6.protected) != 1 || v6.protected[0] != "fd00:db8::/32" {
		t.Errorf("v6 protected = %v, want just the v6 range — a v6 range enforced by iptables is not "+
			"enforced at all, and a dual-stack client reaches it by preferring AAAA", v6.protected)
	}
	if len(v6.exempt) != 1 || v6.exempt[0] != "fd00:db8::1" {
		t.Errorf("v6 exempt = %v, want the v6 exemption in the v6 plan", v6.exempt)
	}
	// The gateway is v4, so it exempts in the v4 plan only. A v6-only gateway with v6 protected ranges
	// is the caller's job to configure; what must never happen is an exemption landing in the wrong
	// firewall, where it silently does nothing.
	if len(v4.exempt) != 1 || v4.exempt[0] != "10.0.0.1" {
		t.Errorf("v4 exempt = %v, want the gateway", v4.exempt)
	}
}

// A CONFIGURATION THAT WOULD GUARD NOTHING, OR BLOCK EVERYTHING, IS REFUSED.
//
// Each of these installs rules, reports success, and is wrong in a way that reads as working.
func TestAConfigurationThatCannotWorkIsRefused(t *testing.T) {
	if _, _, err := (Config{Protected: []string{"10.0.0.0/8"}}).split(); !errors.Is(err, ErrNoGateway) {
		t.Errorf("a guard with no gateway = %v, want ErrNoGateway — it rejects traffic to the gateway "+
			"too, so the endpoint loses the protected services entirely", err)
	}
	if _, _, err := (Config{Gateway: "10.0.0.1"}).split(); !errors.Is(err, ErrNoProtected) {
		t.Errorf("a guard with nothing protected = %v, want ErrNoProtected — it installs rules, reports "+
			"success and changes no behaviour, which reads as coverage", err)
	}
	// An unparseable destination is refused rather than skipped: a silently-skipped range is a hole in
	// the guard that reports success, in exactly the range somebody typed carefully enough to get
	// slightly wrong.
	if _, _, err := (Config{Gateway: "10.0.0.1", Protected: []string{"payroll.corp.example"}}).split(); err == nil {
		t.Error("a hostname was accepted as a protected range — it cannot become a firewall rule, so " +
			"that range would be silently unguarded while the guard reported success")
	}
	if _, _, err := (Config{Gateway: "not-an-ip", Protected: []string{"10.0.0.0/8"}}).split(); err == nil {
		t.Error("an unparseable gateway was accepted — the exemption would not install and the guard " +
			"would block its own permitted path")
	}
}

// THE ATTEMPT COUNT IS THE DETECTION HALF, and it must never report a reassuring zero it did not measure.
//
// A rejected connection to the payroll database from a laptop is a person or a process going around the
// broker. That is a finding whether or not it succeeded — and "no attempts" versus "we could not tell"
// are opposite answers to the only question this number is asked.
func TestAttemptsAreCountedAndAFailureIsNeverAZero(t *testing.T) {
	const listing = `Chain OPENSHIELD_ZTBYPASS (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 RETURN     all  --  *      *       0.0.0.0/0            10.0.0.1
      12      720 REJECT     all  --  *      *       0.0.0.0/0            10.0.0.0/24          reject-with icmp-admin-prohibited
       5      300 REJECT     all  --  *      *       0.0.0.0/0            10.1.0.0/16          reject-with icmp-admin-prohibited
`
	n, err := ParseAttempts(listing)
	if err != nil {
		t.Fatalf("parsing a normal listing: %v", err)
	}
	if n != 17 {
		t.Fatalf("attempts = %d, want 17 (12+5) — the RETURN row must not be counted as an attempt, and "+
			"every REJECT rule must be", n)
	}

	for _, tc := range []struct{ name, in, why string }{
		{"no chain", "Chain INPUT (policy ACCEPT)\n",
			"the guard is not installed, which is not the same as no attempts having been made"},
		{"chain with no reject", "Chain OPENSHIELD_ZTBYPASS (1 references)\n    pkts bytes target\n",
			"a chain with no REJECT rule guards nothing; zero attempts against it is a true statement " +
				"about a guard that is not guarding"},
		{"unreadable count", "Chain OPENSHIELD_ZTBYPASS (1 references)\n  many 720 REJECT all -- * * 0.0.0.0/0 10.0.0.0/24\n",
			"an unparsed counter must not become a zero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseAttempts(tc.in)
			if err == nil {
				t.Fatalf("ParseAttempts returned %d and no error: %s", got, tc.why)
			}
			if got != 0 {
				t.Fatalf("a failing parse returned %d; it must return the error, and the caller must "+
					"not read the value", got)
			}
		})
	}
}

// The teardown is a single-target cleanup that cannot touch an operator's own rules.
func TestTeardownOnlyTouchesOurOwnChain(t *testing.T) {
	for _, args := range removeArgs() {
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, chain) {
			t.Fatalf("teardown step %q does not name %s — a cleanup that reaches beyond our own chain "+
				"can delete rules this product did not install", joined, chain)
		}
	}
}
