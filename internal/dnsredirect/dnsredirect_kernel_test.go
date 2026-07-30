//go:build linux

package dnsredirect

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/dnssink"
)

const testMark = 0x1d5

// buildQuery builds a minimal DNS A query for name with a transaction id.
func buildQuery(id uint16, name string) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	return append(msg, 0x00, 0x00, 0x01, 0x00, 0x01) // root, QTYPE=A, QCLASS=IN
}

// rcode returns the RCODE (low nibble of byte 3) of a DNS message, or -1 if too short.
func rcode(msg []byte) int {
	if len(msg) < 4 {
		return -1
	}
	return int(msg[3] & 0x0f)
}

// clearRedirectState removes BOTH redirect chains, before a test and after it.
//
// THIS IS WHY THE PACKAGE WAS FLAKY UNDER ROOT while every test passed alone. There are two chains — the
// transparent OUTPUT redirect (Install/Remove) and the forwarded PREROUTING one
// (InstallForwarded/RemoveForwarded) — and each test only ever cleared ITS OWN. So whichever kind ran last
// left a rule that redirected the next test's traffic to a resolver port that had since closed, and the
// symptom was `connection refused` against the canned upstream, in a DIFFERENT test on each run depending
// on ordering.
//
// Clearing both, before AND after, makes each test independent of what ran before it — including a previous
// test that failed partway and never reached its own teardown, which is exactly when this matters.
func clearRedirectState(t *testing.T) {
	t.Helper()
	clear := func() {
		_ = Remove(nil)
		_ = RemoveForwarded(nil)
	}
	clear()
	t.Cleanup(clear)
}

// cannedUpstream is a UDP DNS server answering every query NOERROR (RCODE 0). Reaching it proves the
// resolver's marked forward escaped the redirect. It returns the address it bound.
//
// upstreamSeq hands each test its own loopback address, and that is what finally made this package
// deterministic under root.
//
// CONNTRACK IS THE REASON. A nat REDIRECT decision is cached PER FLOW, and removing the rule does not flush
// the entries it created — a UDP conntrack entry outlives the test by ~30s. So a later query whose source
// port happened to collide with an earlier one was still DNAT'd to a resolver port that had since closed,
// and arrived as `connection refused`. That is why the package passed test-by-test, passed the first run,
// and failed the next: the damage was done by the PREVIOUS run, not by anything in the current one.
//
// Flushing would need the conntrack tool, which is not installed here and would be one more thing a
// contributor has to have. A DISTINCT DESTINATION per test is a different conntrack tuple, so no stale
// entry can match — no tooling, and it makes each test independent by construction rather than by cleanup.
var upstreamSeq atomic.Uint32

func cannedUpstream(t *testing.T) string {
	t.Helper()
	// 127.0.0.2, .3, .4 … all local, none of them systemd-resolved's .53/.54.
	addr := fmt.Sprintf("127.0.0.%d:53", 2+upstreamSeq.Add(1)%40)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Skipf("cannot bind the canned upstream %s: %v", addr, err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			reply := make([]byte, n)
			copy(reply, buf[:n])
			reply[2] |= 0x80 // QR = 1 (response)
			reply[3] = 0x00  // RCODE = 0 (NOERROR)
			_, _ = pc.WriteTo(reply, from)
		}
	}()
	return addr
}

// dnsQuery sends one query to addr and returns the response (or an error/timeout).
func dnsQuery(addr string, q []byte) ([]byte, error) {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	resp := make([]byte, 4096)
	n, err := c.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp[:n], nil
}

func requireRedirect(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("transparent :53 redirect needs root (SO_MARK + nat REDIRECT are CAP_NET_ADMIN)")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		if _, err2 := exec.LookPath("nft"); err2 != nil {
			t.Skip("neither iptables nor nft present")
		}
	}

	// BOTH CHAINS ARE CLEARED, before this test and after it, and this is what made the package pass
	// test-by-test and fail as a whole under real root (KERNEL-1).
	//
	// There are two: the transparent OUTPUT redirect (Install/Remove) and the forwarded PREROUTING one
	// (InstallForwarded/RemoveForwarded). Every test cleared only ITS OWN kind, so whichever ran last left
	// a rule that redirected the next test's traffic to a resolver port that had since closed — surfacing
	// as `connection refused` against the canned upstream, in a DIFFERENT test each run depending on
	// ordering. Nobody saw it because root-gated tests skip everywhere except a VM somebody remembers.
	//
	// Before AND after, because "after" alone does not help a test whose predecessor failed partway and
	// never reached its own teardown — which is precisely when the leftovers appear.
	clear := func() {
		_ = Remove(nil)
		_ = RemoveForwarded(nil)
	}
	clear()
	t.Cleanup(clear)
}

// startResolver binds the sinkhole resolver on 127.0.0.1:0 (forwarding to the canned 127.0.0.2:53 upstream
// with the loop-break mark, sinkholing evil.example) and returns its port.
func startResolver(t *testing.T, upstream string) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind resolver: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	r := dnssink.Resolver{
		Upstream: upstream,
		Mark:     testMark,
		Blocked:  func(n string) bool { return n == "evil.example" },
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go r.Serve(ctx, pc)
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// TestTransparentRedirectSinkholesUnconfiguredClient is the gated proof (run on the VM): with the redirect
// installed, a client that points at 127.0.0.2:53 (never told about the resolver) is transparently
// sinkholed for a blocked domain AND still resolves a normal domain — the latter only works because the
// resolver's own marked upstream forward ESCAPES the redirect (the loop-break).
func TestTransparentRedirectSinkholesUnconfiguredClient(t *testing.T) {
	requireRedirect(t)
	upstream := cannedUpstream(t)
	port := startResolver(t, upstream)

	if err := Install(port, testMark, nil); err != nil {
		t.Fatalf("install redirect: %v", err)
	}
	defer Remove(nil)

	// A blocked domain, queried against 127.0.0.2:53 (the client's configured DNS) → transparently
	// redirected to the resolver → NXDOMAIN.
	resp, err := dnsQuery(upstream, buildQuery(0x1111, "evil.example"))
	if err != nil {
		t.Fatalf("blocked query got no response: %v", err)
	}
	if rcode(resp) != 3 {
		t.Fatalf("blocked domain: RCODE = %d, want 3 (NXDOMAIN) — the client was not transparently sinkholed", rcode(resp))
	}

	// A normal domain → resolver forwards (marked, escaping the redirect) to the real upstream → NOERROR.
	resp, err = dnsQuery(upstream, buildQuery(0x2222, "good.example"))
	if err != nil {
		t.Fatalf("normal query got no response (the loop-break failed?): %v", err)
	}
	if rcode(resp) != 0 {
		t.Fatalf("normal domain: RCODE = %d, want 0 (NOERROR from upstream)", rcode(resp))
	}
}

// TestWithoutMarkExemptionResolutionBreaks is the in-test mutation of the loop-break: installing the
// redirect WITHOUT the mark exemption captures the resolver's own upstream forward and loops it back, so a
// normal query is never answered. This proves the exemption is load-bearing, not decorative.
func TestWithoutMarkExemptionResolutionBreaks(t *testing.T) {
	requireRedirect(t)
	upstream := cannedUpstream(t)
	port := startResolver(t, upstream)

	if err := installBackend(port, testMark, false, nil); err != nil { // exempt=false → the mutation
		t.Fatalf("install redirect (no exemption): %v", err)
	}
	defer Remove(nil)

	// A blocked domain is still sinkholed (the resolver answers before forwarding).
	if resp, err := dnsQuery(upstream, buildQuery(0x3333, "evil.example")); err == nil && rcode(resp) != 3 {
		t.Fatalf("blocked domain: RCODE = %d, want 3", rcode(resp))
	}
	// A normal domain loops (resolver forward redirected back into itself) → no answer → timeout.
	if resp, err := dnsQuery(upstream, buildQuery(0x4444, "good.example")); err == nil {
		t.Fatalf("without the mark exemption a normal query must NOT be answerable, got RCODE %d", rcode(resp))
	}
}
