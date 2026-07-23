//go:build linux

package gateway

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// ruleInstalled reports whether the exact TPROXY PREROUTING rule for dport is present (iptables -C exits 0).
func ruleInstalled(dport, listenPort, mark int) bool {
	spec := tproxyRuleSpec(dport, listenPort, mark) // {"-t","mangle","PREROUTING",...}
	args := append([]string{spec[0], spec[1], "-C"}, spec[2:]...)
	return exec.Command("iptables", args...).Run() == nil
}

// TestRuleLifecycleRemovesRulesWhenServerDies is the gated proof (inc-4b): with RunTProxyWithRules serving,
// the TPROXY rule is present and a forwarded flow is spliced; the moment the listener is closed (the server
// stops) with the context still live, the rule is REMOVED — the redirect never outlives the listener.
func TestRuleLifecycleRemovesRulesWhenServerDies(t *testing.T) {
	requireTProxy(t)
	setupTopologyNoRules(t)

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
			go func(c net.Conn) { defer c.Close(); buf := make([]byte, 64); n, _ := c.Read(buf); c.Write(buf[:n]) }(c)
		}
	}()

	ln, err := ListenTransparent(tproxyLn)
	if err != nil {
		t.Fatalf("transparent listen: %v", err)
	}
	srv := &TProxyServer{
		decide: func(_ context.Context, origDst, _ net.Addr, _ FlowHint) (bool, error) {
			host, _, _ := net.SplitHostPort(origDst.String())
			return host == denyDst, nil
		},
		dial: func(origDst net.Addr) (net.Conn, error) { return net.Dial("tcp", origDst.String()) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(func() { RemoveTProxyRules(9998, []int{9999}, 1, 100, nil) })

	go RunTProxyWithRules(ctx, ln, srv, 9998, []int{9999}, 1, 100, nil)
	time.Sleep(300 * time.Millisecond) // let it install + arm

	if !ruleInstalled(9999, 9998, 1) {
		t.Fatal("the TPROXY rule was not installed while the server is running")
	}
	if out, err := nsConnect(allowDst, "PING"); err != nil || !strings.Contains(out, "PING") {
		t.Fatalf("allowed flow should splice while the plane is up: %v %q", err, out)
	}

	// Simulate the server dying (NOT a ctx cancel): close the listener → Serve returns → rules removed.
	ln.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !ruleInstalled(9999, 9998, 1) {
			return // rule removed when the server stopped — the invariant holds
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the TPROXY rule was NOT removed after the server stopped — it outlived the listener (traffic would be black-holed)")
}
