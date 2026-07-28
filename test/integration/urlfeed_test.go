//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// THE REMOTE IOC FEED (NIPS-2), pulled by the running gateway.
//
// `OPENSHIELD_IOC_FEED_URL` moves the threat list off the box, which is how a fleet gets one list instead
// of N copies — and introduces a dependency whose failure modes decide whether the gateway is still an
// IPS when the feed server is down. Two of them are opposite by design and both had to be checked:
//
//   - the INITIAL fetch is fail-fast, because a gateway that starts with an empty feed is an IPS that
//     blocks nothing while reporting itself healthy;
//   - a later REFRESH is serve-stale, because a feed-server outage must not disarm a gateway that
//     already has a good list.
//
// Getting those the wrong way round is entirely plausible and would look fine in a log.

// feedServer serves an IOC feed over HTTP and can be switched to fail, so an outage is a real HTTP
// outage rather than a mocked one.
type feedServer struct {
	mu       sync.Mutex
	body     string
	status   int
	requests int
	ifNone   []string // the If-None-Match values it was asked with
	addr     string
}

func startFeedServer(t *testing.T, body string) *feedServer {
	t.Helper()
	f := &feedServer{body: body, status: http.StatusOK}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = ln.Addr().String()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests++
		f.ifNone = append(f.ifNone, r.Header.Get("If-None-Match"))
		body, status := f.body, f.status
		f.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		// A stable ETag over the body, so an unchanged feed can answer 304 on the next pull.
		w.Header().Set("ETag", `"feed-`+etagOf(body)+`"`)
		if match := r.Header.Get("If-None-Match"); match != "" && match == `"feed-`+etagOf(body)+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(body))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

// etagOf is a content hash, so an unchanged body yields the same ETag and the next pull can be answered
// 304 — which is the behaviour under test.
func etagOf(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:8])
}

func (f *feedServer) fail(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
}

func (f *feedServer) hits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func (f *feedServer) conditionalPulls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.ifNone {
		if v != "" {
			n++
		}
	}
	return n
}

// TestARemoteIocFeedArmsTheGatewayAndPullsConditionally.
//
// The conditional half is not politeness. A gateway pulling a large public feed on a short interval
// without `If-None-Match` re-downloads and RE-PARSES it every time — the parser is the untrusted-input
// surface, so needless re-parsing is needless exposure, on top of the bandwidth.
func TestARemoteIocFeedArmsTheGatewayAndPullsConditionally(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	host, origin := iocOrigin(t)
	feeds := startFeedServer(t, "ip "+host+"\n")

	policy := filepath.Join(work, "block.rego")
	if err := os.WriteFile(policy, []byte(blockOnThreatPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	gw, addr := startGateway(t, stack,
		"OPENSHIELD_IOC_FEED_URL=http://"+feeds.addr+"/ioc",
		"OPENSHIELD_IOC_FEED_URL_RELOAD=1s",
		"OPENSHIELD_POLICY_CUSTOM="+policy,
		"OPENSHIELD_ENFORCE=1")
	gw.WaitForOutput("remote IOC feed pull enabled", 60*time.Second)

	resp, err := proxyClient(t, addr).Get("http://" + origin.addr + "/anything")
	if err != nil {
		t.Fatalf("proxying: %v\n%s", err, gw.Output())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a destination named by the REMOTE feed returned %d, want 403 — the feed was fetched "+
			"and armed nothing\n%s", resp.StatusCode, gw.Output())
	}

	// Let several refresh intervals pass, then check the pulls were CONDITIONAL.
	Eventually(t, 30*time.Second, "several refresh pulls", func() bool { return feeds.hits() >= 3 })
	if n := feeds.conditionalPulls(); n == 0 {
		t.Errorf("%d pulls and not one carried If-None-Match — an unconditional pull re-downloads and "+
			"RE-PARSES the whole list every interval, and the parser is the untrusted-input surface",
			feeds.hits())
	}
}

// TestAFeedServerOutageDoesNotDisarmTheGateway is the serve-stale half.
//
// THE ORDER MATTERS, as it did for the local feed and the CASB catalog: the destination must be BLOCKED
// before the outage, so "still blocked" afterwards cannot be satisfied by a gateway that was never
// blocking. Written the other way round the assertion is free.
func TestAFeedServerOutageDoesNotDisarmTheGateway(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	host, origin := iocOrigin(t)
	feeds := startFeedServer(t, "ip "+host+"\n")

	policy := filepath.Join(work, "block.rego")
	if err := os.WriteFile(policy, []byte(blockOnThreatPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	gw, addr := startGateway(t, stack,
		"OPENSHIELD_IOC_FEED_URL=http://"+feeds.addr+"/ioc",
		"OPENSHIELD_IOC_FEED_URL_RELOAD=1s",
		"OPENSHIELD_POLICY_CUSTOM="+policy,
		"OPENSHIELD_ENFORCE=1")
	gw.WaitForOutput("remote IOC feed pull enabled", 60*time.Second)

	get := func() int {
		t.Helper()
		resp, err := proxyClient(t, addr).Get("http://" + origin.addr + "/anything")
		if err != nil {
			t.Fatalf("proxying: %v\n%s", err, gw.Output())
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(); code != http.StatusForbidden {
		t.Fatalf("the destination was not blocked BEFORE the outage (%d) — the serve-stale assertion "+
			"below would then be free\n%s", code, gw.Output())
	}

	// THE FEED SERVER DIES.
	feeds.fail(http.StatusInternalServerError)
	gw.WaitForOutput("remote IOC feed refresh failed", 60*time.Second)

	if code := get(); code != http.StatusForbidden {
		t.Errorf("the gateway stopped blocking after the FEED SERVER failed (%d). An IPS that disarms "+
			"when its feed host has a bad afternoon is worse than one with no feed at all, because the "+
			"console still shows threat intel configured\n%s", code, gw.Output())
	}
	if n := origin.hits.Load(); n != 0 {
		t.Errorf("the known-bad destination received %d request(s) during the outage", n)
	}
}

// TestAnUnreachableFeedUrlStopsTheGatewayStarting is the opposite rule, and the pair is the point.
//
// A refresh failure is tolerated; the INITIAL fetch is not. A gateway that starts with an empty feed
// because its URL was mistyped is an IPS that blocks nothing and says it is active — the failure this
// whole audit exists to find. The asymmetry is deliberate and is only visible by testing both.
func TestAnUnreachableFeedUrlStopsTheGatewayStarting(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	// A port nothing is listening on: the operator's typo, or a feed host down at deploy time.
	dead := "127.0.0.1:" + freePort(t)

	out := refuseToStart(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "gw-signer.state"),
		"OPENSHIELD_IOC_FEED_URL=http://" + dead + "/ioc",
	})
	if !contains(out, "fetching IOC feed URL") {
		t.Errorf("the refusal does not name the feed fetch, so an operator cannot tell it from any other "+
			"startup failure:\n%s", out)
	}
}
