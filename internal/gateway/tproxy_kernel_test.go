//go:build linux

package gateway

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// requireTProxy skips unless this is a root Linux host where an IP_TRANSPARENT listener can be
// created and the ip/iptables tools exist. Gated like the swtpm/exec-perm tests: run on the
// rooted VM (and a privileged CI job), skipped elsewhere.
func requireTProxy(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("tproxy kernel test needs root (CAP_NET_ADMIN for IP_TRANSPARENT + TPROXY)")
	}
	ln, err := ListenTransparent("127.0.0.1:0")
	if err != nil {
		t.Skipf("IP_TRANSPARENT unavailable: %v", err)
	}
	ln.Close()
	for _, tool := range []string{"ip", "iptables"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found", tool)
		}
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// tryRun runs a command, ignoring errors (for idempotent cleanup).
func tryRun(name string, args ...string) { _ = exec.Command(name, args...).Run() }

const (
	nsName   = "osxt1"
	vethHost = "osxt-h"
	vethNS   = "osxt-n"
	hostIP   = "10.200.0.1"
	nsIP     = "10.200.0.2"
	dstNet   = "10.202.0.0/24"
	allowDst = "10.202.0.1" // an echo server lives here (allowed)
	denyDst  = "10.202.0.2" // blocked by policy
	dstPort  = "9999"
	tproxyLn = "0.0.0.0:9998"
)

// TestTProxyKernelRedirect is the real proof (NIPS-1): a TCP flow FROM a network namespace,
// TPROXY-redirected to the transparent listener, is DROPPED when its original destination is
// policy-blocked and SPLICED (reaches a real echo server) when allowed — the original
// destination recovered from the redirected connection.
//
// Mutation (the listener omits IP_TRANSPARENT, or handleFlow ignores block): the redirect
// fails / the denied flow connects → this test FAILs.
func TestTProxyKernelRedirect(t *testing.T) {
	requireTProxy(t)
	setupTopology(t)

	// A real echo server bound to the ALLOW destination (the flow is spliced to it).
	echoLn, err := net.Listen("tcp", allowDst+":"+dstPort)
	if err != nil {
		t.Fatalf("bind echo on %s: %v", allowDst, err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); buf := make([]byte, 64); n, _ := c.Read(buf); c.Write(buf[:n]) }(c)
		}
	}()

	// The transparent listener + server: block the DENY destination, allow the rest.
	ln, err := ListenTransparent(tproxyLn)
	if err != nil {
		t.Fatalf("transparent listen: %v", err)
	}
	defer ln.Close()
	srv := &TProxyServer{
		decide: func(_ context.Context, origDst, _ net.Addr, _ FlowHint) (bool, error) {
			host, _, _ := net.SplitHostPort(origDst.String())
			return host == denyDst, nil
		},
		dial: func(origDst net.Addr) (net.Conn, error) { return net.Dial("tcp", origDst.String()) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)
	time.Sleep(200 * time.Millisecond)

	// From the namespace: a flow to the ALLOWED dst is spliced and echoes back.
	if out, err := nsConnect(allowDst, "PING"); err != nil {
		t.Fatalf("allowed flow failed (should splice to the echo server): %v\n%s", err, out)
	} else if !strings.Contains(out, "PING") {
		t.Fatalf("allowed flow did not echo: %q", out)
	}

	// From the namespace: a flow to the DENIED dst is dropped (no echo; connection refused/closed).
	if out, err := nsConnect(denyDst, "PING"); err == nil && strings.Contains(out, "PING") {
		t.Fatalf("the DENIED flow was echoed — inline block did not drop it: %q", out)
	}
}

// setupTopology builds ns + veth + forwarding + TPROXY rules, with cleanup registered.
func setupTopology(t *testing.T) {
	t.Helper()
	cleanup := func() {
		tryRun("ip", "netns", "del", nsName)
		tryRun("ip", "link", "del", vethHost)
		tryRun("iptables", "-t", "mangle", "-F", "PREROUTING")
		tryRun("ip", "rule", "del", "fwmark", "1", "lookup", "100")
		tryRun("ip", "route", "flush", "table", "100")
		tryRun("ip", "addr", "del", allowDst+"/32", "dev", "lo")
	}
	cleanup() // clear any stale state from a previous run
	t.Cleanup(cleanup)

	run(t, "ip", "netns", "add", nsName)
	run(t, "ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNS)
	run(t, "ip", "link", "set", vethNS, "netns", nsName)
	run(t, "ip", "addr", "add", hostIP+"/24", "dev", vethHost)
	run(t, "ip", "link", "set", vethHost, "up")
	run(t, "ip", "netns", "exec", nsName, "ip", "addr", "add", nsIP+"/24", "dev", vethNS)
	run(t, "ip", "netns", "exec", nsName, "ip", "link", "set", vethNS, "up")
	run(t, "ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up")
	// Route the destination network from the ns back through the host (which forwards + TPROXYs).
	run(t, "ip", "netns", "exec", nsName, "ip", "route", "add", dstNet, "via", hostIP)
	// The host owns the ALLOW dst locally (the echo server binds it) and forwards.
	run(t, "ip", "addr", "add", allowDst+"/32", "dev", "lo")
	run(t, "sysctl", "-wq", "net.ipv4.ip_forward=1")
	// TPROXY: mark + local route so the redirected packet is delivered locally to the listener.
	run(t, "ip", "rule", "add", "fwmark", "1", "lookup", "100")
	run(t, "ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100")
	run(t, "iptables", "-t", "mangle", "-A", "PREROUTING", "-i", vethHost, "-p", "tcp",
		"--dport", dstPort, "-j", "TPROXY", "--on-port", "9998", "--tproxy-mark", "1")
	t.Cleanup(func() { tryRun("ip", "addr", "del", allowDst+"/32", "dev", "lo") })
}

// nsConnect opens a TCP connection FROM the namespace to dst:dstPort, sends msg, and returns
// whatever comes back within a short timeout. It uses a bash /dev/tcp one-liner via ip netns exec.
func nsConnect(dst, msg string) (string, error) {
	script := fmt.Sprintf(`exec 3<>/dev/tcp/%s/%s || exit 1; printf '%s' >&3; timeout 1 cat <&3`, dst, dstPort, msg)
	out, err := exec.Command("ip", "netns", "exec", nsName, "bash", "-c", script).CombinedOutput()
	return string(out), err
}

// nsConnectRaw sends arbitrary bytes (base64-encoded on the wire, decoded in the ns) FROM the
// namespace to dst:dstPort and returns whatever comes back within a short timeout.
func nsConnectRaw(dst string, payload []byte) (string, error) {
	b64 := base64.StdEncoding.EncodeToString(payload)
	script := fmt.Sprintf(`exec 3<>/dev/tcp/%s/%s || exit 1; printf '%s' | base64 -d >&3; timeout 1 cat <&3 | wc -c`, dst, dstPort, b64)
	out, err := exec.Command("ip", "netns", "exec", nsName, "bash", "-c", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// TestTProxyKernelBlocksBySNI (NIPS-1 increment 2): a redirected flow to an ALLOWED destination IP
// is DROPPED when its ClientHello SNI is policy-blocked, and SPLICED (reaches the echo server) when
// the SNI is benign — the domain recovered from the peeked handshake, proven on a real TPROXY path.
func TestTProxyKernelBlocksBySNI(t *testing.T) {
	requireTProxy(t)
	setupTopology(t)

	// Echo server on the allowed dst IP; it counts bytes it receives (the splice target).
	echoLn, err := net.Listen("tcp", allowDst+":"+dstPort)
	if err != nil {
		t.Fatalf("bind echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()

	ln, err := ListenTransparent(tproxyLn)
	if err != nil {
		t.Fatalf("transparent listen: %v", err)
	}
	defer ln.Close()
	// Block by SNI only (the dst IP is NOT blocked): proves the SNI peek drives the decision.
	srv := &TProxyServer{
		decide: func(_ context.Context, _ net.Addr, _ net.Addr, h FlowHint) (bool, error) {
			return h.SNI == "blocked.example.com", nil
		},
		dial: func(origDst net.Addr) (net.Conn, error) { return net.Dial("tcp", origDst.String()) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)
	time.Sleep(200 * time.Millisecond)

	blockedHello := clientHelloFor(t, "blocked.example.com")
	okHello := clientHelloFor(t, "ok.example.com")

	// Benign SNI → spliced: the echo server receives (and echoes) the handshake bytes → wc -c > 0.
	if out, err := nsConnectRaw(allowDst, okHello); err != nil || out == "0" || out == "" {
		t.Fatalf("benign-SNI flow was not spliced (echo bytes=%q err=%v)", out, err)
	}
	// Blocked SNI → dropped: the connection is closed, nothing echoes back → wc -c == 0.
	if out, _ := nsConnectRaw(allowDst, blockedHello); out != "0" && out != "" {
		t.Fatalf("blocked-SNI flow was NOT dropped (echoed %s bytes) — the SNI peek did not block it", out)
	}
}
