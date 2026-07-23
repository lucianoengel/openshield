//go:build linux

package gateway

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestSuperviseSelfHealsAfterListenerDeath is the gated proof (inc-4c): with the supervised plane serving, a
// forwarded flow is spliced; when the current listener is KILLED the supervisor re-arms (new listener +
// reinstalled rules) and a subsequent forwarded flow is spliced AGAIN — the plane self-healed.
func TestSuperviseSelfHealsAfterListenerDeath(t *testing.T) {
	requireTProxy(t)
	setupTopologyNoRules(t)
	t.Cleanup(func() { RemoveTProxyRules(9998, []int{9999}, 1, 100, nil) })

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

	lnCh := make(chan net.Listener, 4)
	arm := func(c context.Context) error {
		ln, err := ListenTransparent(tproxyLn)
		if err != nil {
			return err
		}
		lnCh <- ln
		srv := &TProxyServer{
			decide: func(_ context.Context, origDst, _ net.Addr, _ FlowHint) (bool, error) {
				host, _, _ := net.SplitHostPort(origDst.String())
				return host == denyDst, nil
			},
			dial: func(origDst net.Addr) (net.Conn, error) { return net.Dial("tcp", origDst.String()) },
		}
		RunTProxyWithRules(c, ln, srv, 9998, []int{9999}, 1, 100, nil)
		ln.Close()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go superviseTProxy(ctx, arm, func(c context.Context) bool { return sleepCtx(c, 50*time.Millisecond) }, nil)

	// Generation 1: read the armed listener, let rules install, confirm a flow splices.
	ln1 := recvListener(t, lnCh)
	time.Sleep(300 * time.Millisecond)
	if out, err := nsConnect(allowDst, "PING"); err != nil || !strings.Contains(out, "PING") {
		t.Fatalf("gen-1 flow should splice: %v %q", err, out)
	}

	// Kill the listener → the server stops → rules removed → the supervisor re-arms.
	ln1.Close()

	// Generation 2: a NEW listener must appear (self-heal), and a flow must splice again.
	recvListener(t, lnCh)
	time.Sleep(300 * time.Millisecond) // let the reinstalled rules settle
	if out, err := nsConnect(allowDst, "PING"); err != nil || !strings.Contains(out, "PING") {
		t.Fatalf("gen-2 flow should splice after self-heal: %v %q", err, out)
	}
}

// recvListener reads the next armed listener or fails on timeout (a timeout means the supervisor did not
// re-arm — no self-heal).
func recvListener(t *testing.T, ch <-chan net.Listener) net.Listener {
	t.Helper()
	select {
	case ln := <-ch:
		return ln
	case <-time.After(4 * time.Second):
		t.Fatal("the supervisor did not arm a listener within 4s (self-heal failed)")
		return nil
	}
}
