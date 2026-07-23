//go:build linux

package gateway

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// setupTopologyNoRules builds the ns + veth + forwarding + allow-dst exactly like setupTopology, but does
// NOT install the TPROXY rules — the test under prove installs them via InstallTProxyRules.
func setupTopologyNoRules(t *testing.T) {
	t.Helper()
	cleanup := func() {
		tryRun("ip", "netns", "del", nsName)
		tryRun("ip", "link", "del", vethHost)
		tryRun("ip", "addr", "del", allowDst+"/32", "dev", "lo")
	}
	cleanup()
	t.Cleanup(cleanup)

	run(t, "ip", "netns", "add", nsName)
	run(t, "ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNS)
	run(t, "ip", "link", "set", vethNS, "netns", nsName)
	run(t, "ip", "addr", "add", hostIP+"/24", "dev", vethHost)
	run(t, "ip", "link", "set", vethHost, "up")
	run(t, "ip", "netns", "exec", nsName, "ip", "addr", "add", nsIP+"/24", "dev", vethNS)
	run(t, "ip", "netns", "exec", nsName, "ip", "link", "set", vethNS, "up")
	run(t, "ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up")
	run(t, "ip", "netns", "exec", nsName, "ip", "route", "add", dstNet, "via", hostIP)
	run(t, "ip", "addr", "add", allowDst+"/32", "dev", "lo")
	run(t, "sysctl", "-wq", "net.ipv4.ip_forward=1")
}

// TestTProxySelfInstalledRules proves the SELF-INSTALLED TPROXY plumbing (InstallTProxyRules) delivers a
// forwarded flow to the transparent listener: a flow to a blocked dst is DROPPED and to an allowed dst is
// SPLICED — the same outcome the manual rules give in TestTProxyKernelRedirect, but with OpenShield owning
// the rules. Gated (root + ip/iptables).
func TestTProxySelfInstalledRules(t *testing.T) {
	requireTProxy(t)
	setupTopologyNoRules(t)

	// OpenShield installs the TPROXY rules (mark 1, table 100, dport 9999 → listener 9998).
	if err := InstallTProxyRules(9998, []int{9999}, 1, 100, nil); err != nil {
		t.Fatalf("InstallTProxyRules: %v", err)
	}
	t.Cleanup(func() { RemoveTProxyRules(9998, []int{9999}, 1, 100, nil) })

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

	if out, err := nsConnect(allowDst, "PING"); err != nil {
		t.Fatalf("allowed flow failed (self-installed rules should splice it): %v\n%s", err, out)
	} else if !strings.Contains(out, "PING") {
		t.Fatalf("allowed flow did not echo (self-installed rules did not deliver it): %q", out)
	}

	if out, err := nsConnect(denyDst, "PING"); err == nil && strings.Contains(out, "PING") {
		t.Fatalf("the DENIED flow was echoed — inline block did not drop it: %q", out)
	}
}
