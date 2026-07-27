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

// TestTheTransparentInlinePlaneDropsABlockedFlow covers NIPS-1 (D311).
//
// TPROXY is the inline data plane: a redirected TCP flow is decided through the pipeline and either
// SPLICED to its destination or DROPPED at L4. It is the only path in the product that can stop traffic
// a client never chose to send through a proxy.
//
// IT REQUIRES A GENUINELY FORWARDED FLOW, and that dictates the whole setup. The rule is
// `mangle PREROUTING ! -i lo`: xt_TPROXY only diverts in the PREROUTING hook, and loopback is excluded
// deliberately. My first version connected to 127.0.0.1 from the same host and the flow sailed through —
// which was the TEST being wrong, not the product. So this builds a network namespace with a veth pair,
// puts the client inside it, and routes its traffic through the host, which is what an inline gateway
// actually is.
func TestTheTransparentInlinePlaneDropsABlockedFlow(t *testing.T) {
	requireNetAdmin(t)
	for _, bin := range []string{"ip", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is needed to build the forwarding topology", bin)
		}
	}
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	// TWO NAMESPACES, and that is forced by how TPROXY works rather than chosen for realism.
	//
	//   client(10.77.0.2) ─veth─ host(10.77.0.1 | 10.77.1.1) ─veth─ origin(10.77.1.2)
	//
	// xt_TPROXY diverts in PREROUTING, and only for traffic the host is FORWARDING. My first two
	// attempts put the origin on the host itself — first on loopback (excluded by the rule's `! -i lo`),
	// then on the host's own veth address — and in both the packet was destined to a LOCAL address, so
	// the kernel delivered it straight to the real socket and the flow sailed through. That was the test
	// pointing at a topology the feature does not apply to, twice, reported as a product failure.
	const ns1, ns2 = "osint-tp-c", "osint-tp-o"
	const hostA, client = "10.77.0.1", "10.77.0.2"
	const hostB, origin = "10.77.1.1", "10.77.1.2"
	sh := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	quiet := func(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }
	// Cleanup removes the HOST-side interfaces too, not just the namespaces. A leftover veth still owns
	// its address, so the next run's `ip addr add` lands on a conflicting interface and the topology
	// silently does not route — which cost a full debugging round here, presenting as "the origin is
	// unreachable" rather than as the address clash it was.
	cleanup := func() {
		quiet("ip", "netns", "del", ns1)
		quiet("ip", "netns", "del", ns2)
		for _, l := range []string{"tp-hc", "tp-ho"} {
			quiet("ip", "link", "del", l)
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	sh("ip", "netns", "add", ns1)
	sh("ip", "netns", "add", ns2)
	for _, v := range []struct{ host, peer, ns, hostAddr, nsAddr string }{
		{"tp-hc", "tp-c", ns1, hostA, client},
		{"tp-ho", "tp-o", ns2, hostB, origin},
	} {
		sh("ip", "link", "add", v.host, "type", "veth", "peer", "name", v.peer)
		sh("ip", "link", "set", v.peer, "netns", v.ns)
		sh("ip", "addr", "add", v.hostAddr+"/24", "dev", v.host)
		sh("ip", "link", "set", v.host, "up")
		sh("ip", "netns", "exec", v.ns, "ip", "addr", "add", v.nsAddr+"/24", "dev", v.peer)
		sh("ip", "netns", "exec", v.ns, "ip", "link", "set", v.peer, "up")
		sh("ip", "netns", "exec", v.ns, "ip", "link", "set", "lo", "up")
		sh("ip", "netns", "exec", v.ns, "ip", "route", "add", "default", "via", v.hostAddr)
	}
	quiet("sysctl", "-w", "net.ipv4.ip_forward=1")

	// The origin lives in the far namespace and records each connection to a file the host can read.
	originPort := freePort(t)
	hitFile := filepath.Join(work, "hits")
	originCmd := exec.Command("ip", "netns", "exec", ns2, "python3", "-c", `
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        open(sys.argv[2], "a").write("hit\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"origin-ok")
    def log_message(self, *a): pass
http.server.HTTPServer(("`+origin+`", int(sys.argv[1])), H).serve_forever()
`, originPort, hitFile)
	// Capture the origin's own stderr. Without it a startup failure inside the namespace surfaces only
	// as "unreachable", which reads as a topology problem and sent me looking in the wrong place.
	originErr := &syncBuffer{}
	originCmd.Stderr = originErr
	originCmd.Stdout = originErr
	if err := originCmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = originCmd.Process.Kill() })
	hits := func() int {
		b, err := os.ReadFile(hitFile)
		if err != nil {
			return 0
		}
		return strings.Count(string(b), "hit")
	}
	// The origin must be REACHABLE before the gateway arms, or "the flow was dropped" is
	// indistinguishable from "there was nothing to reach".
	Eventually(t, 30*time.Second, "the origin in the far namespace to answer", func() bool {
		out, _ := exec.Command("ip", "netns", "exec", ns1, "timeout", "3", "bash", "-c",
			"exec 3<>/dev/tcp/"+origin+"/"+originPort+" && printf 'GET / HTTP/1.0\r\n\r\n' >&3 && cat <&3").CombinedOutput()
		if strings.Contains(string(out), "origin-ok") {
			return true
		}
		if e := originErr.String(); e != "" {
			t.Logf("origin stderr: %s", e)
		}
		return false
	})
	baseline := hits()

	policy := filepath.Join(work, "block.rego")
	// BLOCKS UNCONDITIONALLY. An earlier version keyed on `input.event.kind == "EVENT_KIND_NETWORK_FLOW"`
	// and the flow was ALLOWED — the TPROXY rule had matched seven packets, so diversion was working and
	// the pipeline simply did not agree with the test about the kind. A scenario proving "the inline
	// plane drops what the policy blocks" must not also be testing which kind label the path uses.
	if err := os.WriteFile(policy, []byte(`package openshield
import rego.v1
decision := {"action":"BLOCK","reason":"inline test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tproxyPort := freePort(t)
	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
		"OPENSHIELD_ENFORCE=1",
		"OPENSHIELD_TPROXY_LISTEN=0.0.0.0:" + tproxyPort,
		"OPENSHIELD_TPROXY_INSTALL_RULES=1",
		"OPENSHIELD_TPROXY_DPORTS=" + originPort,
	})
	gw.WaitForOutput("NIPS-1 transparent inline plane ACTIVE", 90*time.Second)
	Eventually(t, 60*time.Second, "the TPROXY rules to be installed", tproxyRuleInstalled)
	// AND the listener must be accepting. Waiting only for the rules is waiting on the wrong signal:
	// they are installed before the transparent listener serves, and a client arriving in between is
	// redirected at a socket that is not yet accepting.
	waitTCP(t, "127.0.0.1:"+tproxyPort, 60*time.Second)

	// The client — in its namespace, knowing nothing about any gateway — tries to reach the origin.
	//
	// It reads the WHOLE response. Reading the first nine bytes returns "HTTP/1.0 " — the status line,
	// never the body — so a check for the body string could never match: the reachability probe above
	// looped until it timed out against a perfectly reachable origin, and THIS assertion could never
	// fire, which made it vacuous in exactly the direction that hides a broken control.
	out, _ := exec.Command("ip", "netns", "exec", ns1, "timeout", "5", "bash", "-c",
		"exec 3<>/dev/tcp/"+origin+"/"+originPort+" && printf 'GET / HTTP/1.0\r\n\r\n' >&3 && cat <&3").CombinedOutput()
	if strings.Contains(string(out), "origin-ok") {
		t.Errorf("a BLOCKED flow was SERVED (%q) — the inline plane decides at L4 and must drop, or "+
			"transparent prevention prevents nothing\n%s", out, gw.Output())
	}
	if after := hits(); after != baseline {
		t.Errorf("the blocked flow REACHED its destination (%d → %d) — a drop that happens after the "+
			"origin has seen the request is not a drop", baseline, after)
	}

	// AND THE RULES ARE REMOVED. Same property as the DNS redirect (D310): routing state that outlives
	// its process silently reroutes traffic into a socket that no longer exists.
	gw.Stop()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && tproxyRuleInstalled() {
		time.Sleep(500 * time.Millisecond)
	}
	if tproxyRuleInstalled() {
		t.Errorf("the TPROXY rules SURVIVED the gateway's shutdown — the host still redirects those " +
			"ports to a listener that no longer exists")
	}
}

// tproxyRuleInstalled reports whether the product's TPROXY plumbing is present.
//
// It matches the RULES THEMSELVES rather than a chain name, because there is no named chain to look for:
// xt_TPROXY only diverts in the PREROUTING hook and delivery is unreliable from a user-defined
// sub-chain, so the target sits directly in `mangle PREROUTING`. The first version of this helper
// grepped for "OPENSHIELD_TPROXY" and found nothing while the rules were installed and working — a
// detector looking for a name the product deliberately does not use.
func tproxyRuleInstalled() bool {
	if out, err := exec.Command("iptables", "-t", "mangle", "-S", "PREROUTING").CombinedOutput(); err == nil {
		if strings.Contains(string(out), "-j TPROXY") {
			return true
		}
	}
	if out, err := exec.Command("nft", "list", "table", "ip", "openshield_tproxy").CombinedOutput(); err == nil {
		if strings.Contains(string(out), "tproxy") {
			return true
		}
	}
	// The policy-routing half: a fwmark rule pointing at the product's dedicated table.
	if out, err := exec.Command("ip", "rule", "list").CombinedOutput(); err == nil {
		if strings.Contains(string(out), "lookup 100") {
			return true
		}
	}
	return false
}
