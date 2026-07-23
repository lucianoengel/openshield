//go:build linux

package dnsredirect

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/dnssink"
)

// TestWatchdogBypassesAWedgedResolver is the gated proof (run on the VM): with the redirect active a blocked
// domain is sinkholed; when the resolver is KILLED the watchdog bypasses (removes the redirect) so the same
// query reaches the real upstream directly (NOERROR) instead of hanging in a dead resolver — DNS is never
// wedged.
func TestWatchdogBypassesAWedgedResolver(t *testing.T) {
	requireRedirect(t)
	cannedUpstream(t) // 127.0.0.2:53 answers NOERROR

	// The sinkhole resolver on a high port, blocking evil.example, with its own cancel so we can KILL it.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind resolver: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	resolverCtx, killResolver := context.WithCancel(context.Background())
	go dnssink.Resolver{Upstream: "127.0.0.2:53", Mark: testMark, Blocked: func(n string) bool { return n == "evil.example" }}.Serve(resolverCtx, pc)

	wd := &Watchdog{Port: port, Mark: testMark, Interval: 200 * time.Millisecond, Failures: 2}
	wdCtx, stopWatchdog := context.WithCancel(context.Background())
	defer stopWatchdog()
	go wd.Run(wdCtx)
	time.Sleep(300 * time.Millisecond) // let it install + probe once

	// Redirect active: a blocked domain is transparently sinkholed.
	if resp, err := dnsQuery("127.0.0.2:53", buildQuery(0x1111, "evil.example")); err != nil {
		t.Fatalf("with the redirect active, blocked query got no response: %v", err)
	} else if rcode(resp) != 3 {
		t.Fatalf("with the redirect active, evil.example RCODE = %d, want 3 (NXDOMAIN)", rcode(resp))
	}

	// KILL the resolver, then wait for the watchdog to bypass (Failures * Interval + slack).
	killResolver()
	pc.Close()
	time.Sleep(1500 * time.Millisecond)

	// The redirect is now bypassed: evil.example resolves DIRECTLY at the real upstream (NOERROR) — the
	// sinkhole is out of the way, and crucially the query is ANSWERED rather than dropped into a dead resolver.
	resp, err := dnsQuery("127.0.0.2:53", buildQuery(0x2222, "evil.example"))
	if err != nil {
		t.Fatalf("after the resolver died the query was NOT answered — DNS is wedged (bypass failed): %v", err)
	}
	if rcode(resp) != 0 {
		t.Fatalf("after bypass evil.example RCODE = %d, want 0 (answered directly by the upstream, sinkhole bypassed)", rcode(resp))
	}
}
