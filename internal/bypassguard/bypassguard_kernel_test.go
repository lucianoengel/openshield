//go:build linux

package bypassguard

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// ZT-10 ON A REAL KERNEL. The builder tests next door prove the rules SAY the right thing; only this
// proves they DO it. A firewall rule set that is syntactically perfect and rejects nothing is the exact
// shape of a security control that reports success and protects nobody.
//
// Root-gated (CAP_NET_ADMIN), so it skips everywhere except a VM. Self-contained on loopback: two
// listeners on 127.0.0.x, one standing in for a protected internal service and one for the gateway.

func requireGuard(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the endpoint bypass guard needs root (iptables filter rules are CAP_NET_ADMIN)")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not present")
	}
	// Clear before AND after. "After" alone does not help a test whose predecessor failed partway and
	// left a chain behind — and a leftover REJECT for 127.0.0.0/8 would break every later test in the
	// package in a way that looks like the network, not like a stale rule.
	_ = Remove(nil)
	t.Cleanup(func() { _ = Remove(nil) })
}

// listenOn starts a TCP listener on a loopback alias and returns its address. It accepts and immediately
// replies, so a successful connection is provable rather than assumed.
func listenOn(t *testing.T, host string) string {
	t.Helper()
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Fatalf("listening on %s: %v", host, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("ok\n"))
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

// reach reports whether a TCP connection to addr completes, and the error if not.
func reach(addr string) (bool, error) {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false, err
	}
	_ = c.Close()
	return true, nil
}

// THE HEADLINE: direct traffic to a protected address is REJECTED, and the gateway still works.
//
// Both halves are required. A guard that blocks everything is not enforcement, it is an outage — and
// since the gateway normally lives inside the range it fronts, "the gateway still works" is precisely
// the assertion that the exemption ordering is right on a real kernel and not only in the argv.
func TestDirectTrafficIsRejectedWhileTheGatewayStillWorks(t *testing.T) {
	requireGuard(t)

	protectedAddr := listenOn(t, "127.0.0.9") // stands in for the internal database
	gatewayAddr := listenOn(t, "127.0.0.8")   // stands in for the ZTNA gateway

	// Both are reachable before the guard — otherwise the assertions below would pass against a machine
	// where nothing worked in the first place.
	if ok, err := reach(protectedAddr); !ok {
		t.Fatalf("the protected service was unreachable BEFORE the guard: %v", err)
	}
	if ok, err := reach(gatewayAddr); !ok {
		t.Fatalf("the gateway was unreachable BEFORE the guard: %v", err)
	}

	// The gateway is INSIDE the protected range — the ordinary deployment, and the case the exemption
	// ordering exists for.
	if err := Install(Config{
		Gateway:   "127.0.0.8",
		Protected: []string{"127.0.0.8/29"}, // covers .8 through .15, so both listeners are inside it
	}, nil); err != nil {
		t.Fatalf("installing the guard: %v", err)
	}

	if ok, err := reach(protectedAddr); ok {
		t.Fatal("the protected service is still reachable DIRECTLY — the broker authenticates a device " +
			"and a user, checks posture and risk, and none of it binds if a client can open a socket " +
			"straight to the service")
	} else if err == nil {
		t.Fatal("the dial neither succeeded nor errored")
	}

	if ok, err := reach(gatewayAddr); !ok {
		t.Fatalf("the GATEWAY is unreachable through the guard (%v) — the exemption must precede the "+
			"reject that covers it, or the endpoint loses the protected services entirely and the "+
			"outage looks exactly like the feature working", err)
	}

	// The attempt is counted. This is the detection half, and it is worth more than the blocking: a
	// rejected connection to a protected service is a person or a process going around the broker.
	n, err := Attempts()
	if err != nil {
		t.Fatalf("reading the attempt count: %v", err)
	}
	if n < 1 {
		t.Fatalf("Attempts = %d, want >=1 — the block happened and nothing recorded it, so the bypass "+
			"attempt is invisible to the operator it concerns", n)
	}
}

// REMOVE PUTS THE ENDPOINT BACK, exactly.
//
// A guard whose teardown is partial leaves an endpoint that cannot reach a service and an operator with
// no rule to point at — the worst kind of outage, because the cause has been uninstalled.
func TestRemoveRestoresDirectReachability(t *testing.T) {
	requireGuard(t)

	protectedAddr := listenOn(t, "127.0.0.9")
	if err := Install(Config{Gateway: "127.0.0.8", Protected: []string{"127.0.0.8/29"}}, nil); err != nil {
		t.Fatalf("installing: %v", err)
	}
	if ok, _ := reach(protectedAddr); ok {
		t.Fatal("the guard did not block, so this test cannot show that Remove unblocks")
	}
	if err := Remove(nil); err != nil {
		t.Fatalf("removing: %v", err)
	}
	if ok, err := reach(protectedAddr); !ok {
		t.Fatalf("still blocked after Remove (%v) — a partial teardown leaves an endpoint that cannot "+
			"reach a service and an operator with no rule to point at", err)
	}
	// And a second Remove is not an error: teardown runs on paths that may already be clean.
	if err := Remove(nil); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
}

// RE-INSTALL IS IDEMPOTENT, and the rules do not accumulate.
//
// The guard is installed at agent start, and an agent restarts. Without remove-then-add, each restart
// appends another copy of every rule and another OUTPUT jump — the chain grows without bound and the
// attempt counter starts counting each packet several times, which quietly inflates the one number an
// operator would act on.
func TestReinstallingDoesNotAccumulateRules(t *testing.T) {
	requireGuard(t)

	cfg := Config{Gateway: "127.0.0.8", Protected: []string{"127.0.0.8/29"}}
	for i := 0; i < 3; i++ {
		if err := Install(cfg, nil); err != nil {
			t.Fatalf("install %d: %v", i+1, err)
		}
	}
	out, err := exec.Command("iptables", listArgs()...).CombinedOutput()
	if err != nil {
		t.Fatalf("listing: %v (%s)", err, string(out))
	}
	rejects := 0
	for _, line := range splitLines(string(out)) {
		if fieldsContain(line, "REJECT") {
			rejects++
		}
	}
	if rejects != 1 {
		t.Fatalf("after three installs the chain holds %d REJECT rules, want 1 — each restart would "+
			"otherwise append another copy, the chain would grow without bound, and the attempt counter "+
			"would count one packet several times, inflating the only number an operator acts on\n%s",
			rejects, string(out))
	}

	// The OUTPUT jump must not accumulate either — a duplicate jump is a duplicate traversal.
	hooks, err := exec.Command("iptables", "-L", "OUTPUT", "-n").CombinedOutput()
	if err != nil {
		t.Fatalf("listing OUTPUT: %v", err)
	}
	jumps := 0
	for _, line := range splitLines(string(hooks)) {
		if fieldsContain(line, chain) {
			jumps++
		}
	}
	if jumps != 1 {
		t.Fatalf("OUTPUT holds %d jumps into %s, want 1\n%s", jumps, chain, string(hooks))
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func fieldsContain(line, want string) bool {
	for _, f := range fields(line) {
		if f == want {
			return true
		}
	}
	return false
}

func fields(line string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(line); i++ {
		if i == len(line) || line[i] == ' ' || line[i] == '\t' {
			if start >= 0 {
				out = append(out, line[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	return out
}
