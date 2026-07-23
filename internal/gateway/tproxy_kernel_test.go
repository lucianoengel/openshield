//go:build linux

package gateway

import (
	"context"
	"fmt"
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
		decide: func(_ context.Context, origDst, _ net.Addr) (bool, error) {
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
