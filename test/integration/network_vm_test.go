//go:build integration

package integration

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE TRANSPARENT NETWORK PATHS (D310): the DNS sinkhole and its :53 redirect, and the TPROXY inline
// data plane.
//
// These are the only two capabilities in the product that need CAP_NET_ADMIN, and neither had ever been
// driven from this harness. They are also the two whose failure is least visible: a sinkhole that does
// not bind, or a redirect rule that does not install, leaves a gateway that starts cleanly, logs
// success-adjacent lines, and never sees a packet.
//
// Both are ROOT-GATED and run on the rooted VM through the same build-here/run-there workflow as the
// privileged agent. They SKIP visibly elsewhere, naming what they need.

func requireNetAdmin(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the transparent network paths need root (CAP_NET_ADMIN for nft/iptables and :53) — run " +
			"on the rooted VM with " + BinDirEnv + " pointing at pre-built binaries")
	}
}

// dnsQuery builds a minimal A query and returns the response's RCODE.
//
// Hand-rolled rather than using a resolver library, because the point is what the SINKHOLE answers to a
// client that knows nothing about it — and a library that retried or fell back to another server would
// hide exactly the answer under test.
func dnsQuery(t *testing.T, server, name string) (rcode int, answers int) {
	t.Helper()
	var q []byte
	q = append(q, 0x12, 0x34) // id
	q = append(q, 0x01, 0x00) // standard query, recursion desired
	q = append(q, 0x00, 0x01) // qdcount
	q = append(q, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0x00)
	q = append(q, 0x00, 0x01, 0x00, 0x01) // A, IN

	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	if err != nil {
		t.Fatalf("dialling %s: %v", server, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(q); err != nil {
		t.Fatalf("querying: %v", err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no answer from %s for %q: %v", server, name, err)
	}
	if n < 12 {
		t.Fatalf("short DNS response (%d bytes)", n)
	}
	return int(buf[3] & 0x0f), int(binary.BigEndian.Uint16(buf[6:8]))
}

// TestTheDNSSinkholeRefusesAKnownBadDomainAndForwardsTheRest is NIPS-8's core claim.
func TestTheDNSSinkholeRefusesAKnownBadDomainAndForwardsTheRest(t *testing.T) {
	requireNetAdmin(t)
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	// A canned upstream that answers everything, so "forwarded" is observable without the internet.
	upstreamAddr := startStubDNSAt(t, "127.0.0.1:0")
	feed := filepath.Join(work, "ioc.feed")
	if err := os.WriteFile(feed, []byte("domain evil.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sinkAddr := "127.0.0.1:" + freePort(t)

	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_IOC_FEED=" + feed,
		"OPENSHIELD_DNS_SINK_LISTEN=" + sinkAddr,
		"OPENSHIELD_DNS_UPSTREAM=" + upstreamAddr,
	})
	gw.WaitForOutput("gateway proxying", 90*time.Second)
	waitUDP(t, sinkAddr)

	// A KNOWN-BAD domain is sinkholed. NXDOMAIN rather than a lie about an address: pointing a client at
	// a fake IP is a redirection the client cannot distinguish from a real one.
	rcode, _ := dnsQuery(t, sinkAddr, "evil.example")
	if rcode != 3 {
		t.Errorf("a known-bad domain answered rcode %d, want 3 (NXDOMAIN)", rcode)
	}

	// EVERYTHING ELSE IS FORWARDED. A sinkhole that answers NXDOMAIN to the fleet is an outage, and it
	// is the failure mode a DNS control has to be judged against — this is name resolution.
	rcode, answers := dnsQuery(t, sinkAddr, "good.example")
	if rcode != 0 {
		t.Errorf("an ordinary domain answered rcode %d, want 0 — a resolver that NXDOMAINs the fleet is "+
			"an outage, not a control\n%s", rcode, gw.Output())
	}
	if answers == 0 {
		t.Errorf("the forwarded query returned no answer — the upstream's reply must be relayed, or the " +
			"resolver silently breaks every name it does not block")
	}
}

// TestTheTransparentDNSRedirectCatchesAnUnmodifiedClient is DEPLOY-1's claim.
//
// The redirect is what makes the sinkhole apply to a client that was never configured to use it — which
// is every client. Its subtlety is the LOOP-BREAK: the resolver's own upstream forward is also port 53,
// so a naive redirect sends it back to itself and name resolution stops entirely.
func TestTheTransparentDNSRedirectCatchesAnUnmodifiedClient(t *testing.T) {
	requireNetAdmin(t)
	if _, err := exec.LookPath("nft"); err != nil {
		if _, err2 := exec.LookPath("iptables"); err2 != nil {
			t.Skip("neither nft nor iptables is available to install the redirect")
		}
	}
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	// THE STUB LISTENS ON :53, because the redirect rule matches `udp dport 53`. A stub on an ephemeral
	// port is never redirected, and the scenario would report a product failure that is really a test
	// that pointed its client somewhere the rule does not apply — which is what the first version did.
	const upstreamAddr = "127.0.0.2:53"
	startStubDNSAt(t, upstreamAddr)
	feed := filepath.Join(work, "ioc.feed")
	if err := os.WriteFile(feed, []byte("domain evil.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sinkAddr := "127.0.0.1:" + freePort(t)

	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_IOC_FEED=" + feed,
		"OPENSHIELD_DNS_SINK_LISTEN=" + sinkAddr,
		"OPENSHIELD_DNS_UPSTREAM=" + upstreamAddr,
		"OPENSHIELD_DNS_REDIRECT=local",
	})
	gw.WaitForOutput("gateway proxying", 90*time.Second)
	waitUDP(t, sinkAddr)
	if !contains(gw.Output(), "redirect") {
		t.Fatalf("the gateway did not report installing the DNS redirect\n%s", gw.Output())
	}

	// A client that knows NOTHING about the sinkhole: it queries the stub upstream directly on :53, and
	// the redirect is what should catch it.
	rcode, _ := dnsQuery(t, upstreamAddr, "evil.example")
	if rcode != 3 {
		t.Errorf("an UNMODIFIED client's query for a known-bad domain answered rcode %d, want NXDOMAIN — "+
			"the transparent redirect is what makes the sinkhole apply to clients nobody reconfigured\n%s",
			rcode, gw.Output())
	}

	// THE RULE IS REMOVED WHEN THE GATEWAY STOPS. Host firewall state that outlives the process which
	// installed it is worse than not installing it: a rule pointing at a dead resolver port sends the
	// host's entire :53 traffic nowhere, and nothing on the box explains why name resolution broke.
	// AND THE LOOP-BREAK HOLDS: an ordinary name still resolves. Without the mark exemption the
	// resolver's own forward is redirected back into itself and every non-blocked name times out.
	rcode, answers := dnsQuery(t, upstreamAddr, "good.example")
	if rcode != 0 || answers == 0 {
		t.Errorf("an ordinary name did not resolve through the redirect (rcode=%d answers=%d). The "+
			"resolver's upstream forward is also port 53, so without the firewall-mark exemption it is "+
			"redirected back to itself and name resolution stops for everything\n%s",
			rcode, answers, gw.Output())
	}

	// THE RULE IS REMOVED WHEN THE GATEWAY STOPS. Host firewall state that outlives the process which
	// installed it is worse than never installing it: a rule pointing at a dead resolver port sends the
	// host's entire :53 traffic nowhere, and nothing on the box explains why name resolution broke.
	//
	// Stopped EXPLICITLY rather than in a cleanup — cleanups run LIFO, so one registered here would run
	// before Start's and check while the gateway was still up, which is what the first version did.
	gw.Stop()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && redirectRuleInstalled() {
		time.Sleep(500 * time.Millisecond)
	}
	if redirectRuleInstalled() {
		t.Errorf("the transparent DNS redirect SURVIVED the gateway's shutdown — the host's :53 traffic " +
			"is still redirected to a port nothing is listening on, which breaks name resolution for " +
			"everything with no visible cause")
	}
}

// startStubDNS answers every A query with a fixed address.
//
// addr is explicit because the transparent-redirect scenario needs it on PORT 53: the redirect rule
// matches `udp dport 53`, so a stub on an ephemeral port is never redirected and the scenario would
// prove nothing while looking like a product failure. That is exactly what the first version did.
func startStubDNSAt(t *testing.T, addr string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("binding the stub upstream on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			resp := append([]byte(nil), buf[:n]...)
			resp[2] |= 0x80 // response
			resp[3] = 0x00  // NOERROR
			resp[6], resp[7] = 0x00, 0x01
			// One A answer pointing at a fixed address, with a compression pointer to the question.
			resp = append(resp, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
				0x00, 0x04, 203, 0, 113, 1)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func waitUDP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("udp", addr, time.Second)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("nothing on %s", addr)
}

var _ = fmt.Sprintf

// redirectRuleInstalled reports whether the product's redirect rules are present in the host firewall.
func redirectRuleInstalled() bool {
	for _, c := range [][]string{
		{"nft", "list", "table", "ip", "openshield_dnsredirect"},
		{"iptables", "-t", "nat", "-S"},
	} {
		out, err := exec.Command(c[0], c[1:]...).CombinedOutput()
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToUpper(string(out)), "OPENSHIELD_DNSREDIR") {
			return true
		}
	}
	return false
}
