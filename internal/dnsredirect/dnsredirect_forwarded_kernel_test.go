//go:build linux

package dnsredirect

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/dnssink"
)

const (
	fwdNS     = "osdns1"
	fwdVethH  = "osd-h"
	fwdVethN  = "osd-n"
	fwdHostIP = "10.210.0.1"
	fwdNSIP   = "10.210.0.2"
	fwdDNSNet = "10.211.0.0/24"
	fwdDNSSrv = "10.211.0.53" // the DNS server IP the ns client thinks it is using (forwarded to us)
)

func fwdRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}
func fwdTry(name string, args ...string) { _ = exec.Command(name, args...).Run() }

// setupForwardingTopology builds ns + veth + forwarding, with cleanup (incl. the forwarded redirect).
func setupForwardingTopology(t *testing.T) {
	t.Helper()
	cleanup := func() {
		RemoveForwarded(nil)
		fwdTry("ip", "netns", "del", fwdNS)
		fwdTry("ip", "link", "del", fwdVethH)
	}
	cleanup()
	t.Cleanup(cleanup)

	fwdRun(t, "ip", "netns", "add", fwdNS)
	fwdRun(t, "ip", "link", "add", fwdVethH, "type", "veth", "peer", "name", fwdVethN)
	fwdRun(t, "ip", "link", "set", fwdVethN, "netns", fwdNS)
	fwdRun(t, "ip", "addr", "add", fwdHostIP+"/24", "dev", fwdVethH)
	fwdRun(t, "ip", "link", "set", fwdVethH, "up")
	fwdRun(t, "ip", "netns", "exec", fwdNS, "ip", "addr", "add", fwdNSIP+"/24", "dev", fwdVethN)
	fwdRun(t, "ip", "netns", "exec", fwdNS, "ip", "link", "set", fwdVethN, "up")
	fwdRun(t, "ip", "netns", "exec", fwdNS, "ip", "link", "set", "lo", "up")
	fwdRun(t, "ip", "netns", "exec", fwdNS, "ip", "route", "add", fwdDNSNet, "via", fwdHostIP)
	fwdRun(t, "sysctl", "-wq", "net.ipv4.ip_forward=1")
}

// nsDig runs dig from inside the namespace against the (to-be-forwarded) DNS server IP and returns the
// combined output, so the caller can check the RCODE status line.
func nsDig(t *testing.T, name string) string {
	t.Helper()
	out, _ := exec.Command("ip", "netns", "exec", fwdNS, "dig", "@"+fwdDNSSrv, name, "+time=2", "+tries=1").CombinedOutput()
	return string(out)
}

// TestForwardedRedirectSinkholesGatewayClient is the gated proof (NIPS-8 forwarded/gateway redirect): a
// client BEHIND the gateway (in the netns) whose DNS is forwarded through the host is transparently
// sinkholed for a blocked domain and still resolves a normal one — proving the sinkhole covers forwarded
// client DNS, not only the gateway's own queries.
func TestForwardedRedirectSinkholesGatewayClient(t *testing.T) {
	requireRedirect(t)
	if _, err := exec.LookPath("dig"); err != nil {
		t.Skip("dig not available")
	}
	cannedUpstream(t) // 127.0.0.2:53 answers NOERROR
	setupForwardingTopology(t)

	pc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("bind resolver: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go dnssink.Resolver{Upstream: "127.0.0.2:53", Blocked: func(n string) bool { return n == "evil.example" }}.Serve(ctx, pc)

	if err := InstallForwarded(port, nil); err != nil {
		t.Fatalf("InstallForwarded: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// A blocked domain, forwarded from the ns client → transparently sinkholed → NXDOMAIN.
	if out := nsDig(t, "evil.example"); !strings.Contains(out, "status: NXDOMAIN") {
		t.Fatalf("forwarded blocked query was NOT sinkholed (want NXDOMAIN):\n%s", out)
	}
	// A normal domain → resolver forwards to the real upstream → NOERROR.
	if out := nsDig(t, "good.example"); !strings.Contains(out, "status: NOERROR") {
		t.Fatalf("forwarded normal query was NOT resolved (want NOERROR):\n%s", out)
	}
}
