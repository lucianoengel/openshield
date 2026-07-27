//go:build integration

package integration

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// THE GATEWAY'S DATA PATH — traffic actually proxied through the running binary (D300).
//
// Until now the suite STARTED a gateway and never sent a request through it. Every gateway scenario
// asserted on a startup line, which is the weakest assertion this suite makes and the one that has been
// wrong three times (D294's intent consumption, D296's purpose stamp, D299's kill switch). A proxy that
// comes up cleanly and forwards everything unclassified would have satisfied all of them.
//
// So these drive real HTTP through the real proxy to a real upstream, and assert on what the UPSTREAM
// received — which is the only place the difference between "blocked" and "logged a block" is visible.

// upstream is a local origin server that records what actually reached it.
type upstream struct {
	addr string
	hits atomic.Int64
	body atomic.Value // last body as string
}

// startUpstreamAt listens on a GIVEN address and returns just its hit counter.
//
// The address is explicit for the TPROXY scenario: an origin on loopback can never receive a FORWARDED
// flow, and TPROXY only diverts in PREROUTING on a non-loopback interface.
func startUpstreamAt(t *testing.T, addr string) *atomic.Int64 {
	t.Helper()
	var hits atomic.Int64
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listening on %s: %v", addr, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("origin-ok"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &hits
}

// startUpstream listens on loopback so the gateway subprocess can reach it.
func startUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.body.Store("")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u.addr = ln.Addr().String()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.body.Store(string(b))
		u.hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("origin-ok"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return u
}

// proxyClient sends requests THROUGH the gateway, the way a configured browser does.
func proxyClient(t *testing.T, gatewayAddr string) *http.Client {
	t.Helper()
	pu, err := url.Parse("http://" + gatewayAddr)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
		// A block is a 403 and a redirect is a 302; following either would hide which one happened.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// startGatewayOn runs the real proxy binary against a GIVEN database and returns its address.
//
// The database is explicit because the forward-secure ledger's chain is bound to the signer that started
// it: two gateways sharing one database means the second opens a chain whose keys it does not hold and
// refuses to start — correctly. In a deployment they are separate hosts; here they need separate
// databases to be separate hosts.
func startGatewayOn(t *testing.T, dsn string, extra ...string) (*Process, string) {
	t.Helper()
	addr := "127.0.0.1:" + freePort(t)
	env := append([]string{
		"OPENSHIELD_DSN=" + dsn,
		"OPENSHIELD_LISTEN=" + addr,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(t.TempDir(), "gw-signer.state"),
	}, extra...)
	gw := Start(t, "openshield-gateway", env)
	gw.WaitForOutput("gateway proxying", 90*time.Second)
	waitTCP(t, addr, 60*time.Second)
	return gw, addr
}

func startGateway(t *testing.T, stack *Stack, extra ...string) (*Process, string) {
	t.Helper()
	return startGatewayOn(t, stack.DSN, extra...)
}

const cpfBody = "name,cpf\nalice,111.444.777-35\n"

// TestTheGatewayClassifiesAndAuditsProxiedTraffic is the observe-only default (D1).
//
// The request MUST still reach the upstream: observe-only means observe, and a default that quietly
// broke egress would be discovered in production by everyone at once.
func TestTheGatewayClassifiesAndAuditsProxiedTraffic(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	origin := startUpstream(t)
	gw, addr := startGateway(t, stack)

	resp, err := proxyClient(t, addr).Post("http://"+origin.addr+"/upload", "text/csv", strings.NewReader(cpfBody))
	if err != nil {
		t.Fatalf("proxying a request: %v\n%s", err, gw.Output())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("observe-only returned %d — the DEFAULT must not break egress", resp.StatusCode)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("the upstream received %d requests, want 1", origin.hits.Load())
	}
	if got, _ := origin.body.Load().(string); got != cpfBody {
		t.Errorf("the body reaching the upstream was altered: %q", got)
	}

	// And the flow was CLASSIFIED and recorded. Asserting on the ledger, not the log: an audit trail
	// that exists only in stderr is not an audit trail.
	pool := openPool(t, stack.DSN)
	Eventually(t, 90*time.Second, "the proxied flow to be audited", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n)
		return n > 0
	})
	// The body must NOT be in the ledger. The gateway holds plaintext to proxy it; the evidence store
	// keeps type + confidence + count (D10), and a ledger containing the CPF makes the audit the leak.
	var payload string
	if err := pool.QueryRow(Ctx(t),
		`SELECT coalesce(payload::text,'') FROM audit_entries LIMIT 1`).Scan(&payload); err == nil {
		if contains(payload, "111.444.777-35") || contains(payload, "11144477735") {
			t.Errorf("the proxied BODY reached the ledger:\n%s", payload)
		}
	}
}

// blockOnCPF is a policy that actually blocks. The shipped default emits ALERT or ALLOW and never
// selects an enforcing verb (D1), so with it the enforcing path would have nothing to do and this test
// would be green and empty.
const blockOnCPF = `package openshield
import rego.v1
hit if { some h in input.classification; h.type == "DETECTOR_TYPE_CPF" }
decision := {"action":"BLOCK","reason":"cpf in an upload"} if { hit }
decision := {"action":"ALLOW","reason":"clean"} if { not hit }`

// TestTheGatewayBlocksASensitiveUploadBeforeItLeaves is the claim that matters for a DLP gateway.
//
// THE ASSERTION IS ON THE UPSTREAM. A 403 to the client proves the gateway answered; only an upstream
// that never saw the request proves the data did not leave.
func TestTheGatewayBlocksASensitiveUploadBeforeItLeaves(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	origin := startUpstream(t)
	policy := filepath.Join(t.TempDir(), "block.rego")
	if err := os.WriteFile(policy, []byte(blockOnCPF), 0o600); err != nil {
		t.Fatal(err)
	}
	_, addr := startGateway(t, stack,
		"OPENSHIELD_POLICY_CUSTOM="+policy,
		"OPENSHIELD_ENFORCE=1",
	)
	client := proxyClient(t, addr)

	// A CLEAN request first, so a gateway that blocked everything cannot pass this test.
	clean, err := client.Post("http://"+origin.addr+"/ok", "text/plain", strings.NewReader("nothing sensitive"))
	if err != nil {
		t.Fatal(err)
	}
	clean.Body.Close()
	if clean.StatusCode != http.StatusOK || origin.hits.Load() != 1 {
		t.Fatalf("a CLEAN upload was not forwarded: status=%d upstream hits=%d", clean.StatusCode, origin.hits.Load())
	}

	resp, err := client.Post("http://"+origin.addr+"/upload", "text/csv", strings.NewReader(cpfBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a sensitive upload got %d, want 403", resp.StatusCode)
	}
	// THE POINT: the origin count did not move.
	if got := origin.hits.Load(); got != 1 {
		t.Errorf("the sensitive body REACHED THE UPSTREAM (%d hits, want still 1). A gateway that answers "+
			"403 to the client and forwards anyway has told the operator it prevented an exfiltration it "+
			"did not prevent", got)
	}
}

// TestAThreatIntelMatchAlertsByDefaultAndCanBlock covers NIPS-2 — the destination axis, which does not
// depend on the body at all.
//
// It asserts BOTH halves, and the first half is the one that found a defect: with the SHIPPED default
// policy a matched indicator must produce an ALERT. It did not. No shipped policy read `input.threat`,
// so the engine matched indicators and handed them to a decision layer that ignored them — while the
// gateway logged "NIPS-2 threat-intel engine active". The feature existed everywhere except at the point
// where a match becomes a decision (D300).
func TestAThreatIntelMatchAlertsByDefaultAndCanBlock(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	origin := startUpstream(t)
	host, _, err := net.SplitHostPort(origin.addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	feed := filepath.Join(dir, "ioc.feed")
	if err := os.WriteFile(feed, []byte("ip "+host+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// PART 1: the shipped default. Observe-only, so the flow is FORWARDED — and the match is recorded.
	_, addr := startGateway(t, stack, "OPENSHIELD_IOC_FEED="+feed)
	resp, err := proxyClient(t, addr).Get("http://" + origin.addr + "/anything")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if origin.hits.Load() != 1 {
		t.Fatalf("observe-only did not forward: %d upstream hits", origin.hits.Load())
	}
	pool := openPool(t, stack.DSN)
	Eventually(t, 90*time.Second, "the threat match to be ALERTED on by the default policy", func() bool {
		var n int
		// action 2 = ALERT.
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries WHERE action = 2`).Scan(&n)
		return n > 0
	})

	// PART 2: an operator who raises it to BLOCK gets a block — and the flow never reaches the
	// destination. The closed action set means this is the operator's deliberate choice, not a default.
	policy := filepath.Join(dir, "block-threat.rego")
	const blockOnThreat = `package openshield
import rego.v1
decision := {"action":"BLOCK","reason":"known-bad destination"} if { count(input.threat.matches) > 0 }
decision := {"action":"ALLOW","reason":"clean"} if { count(input.threat.matches) == 0 }`
	if err := os.WriteFile(policy, []byte(blockOnThreat), 0o600); err != nil {
		t.Fatal(err)
	}
	_, addr2 := startGatewayOn(t, stack.DSNFor(t, "gwblock"),
		"OPENSHIELD_IOC_FEED="+feed, "OPENSHIELD_POLICY_CUSTOM="+policy, "OPENSHIELD_ENFORCE=1")

	hitsBefore := origin.hits.Load()
	resp2, err := proxyClient(t, addr2).Get("http://" + origin.addr + "/anything")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Errorf("a request to a KNOWN-BAD destination returned 200 under a blocking policy")
	}
	if got := origin.hits.Load(); got != hitsBefore {
		t.Errorf("the request REACHED a known-bad destination (%d → %d hits) — a threat-intel engine "+
			"that logs the match and forwards the flow is a log, not a control", hitsBefore, got)
	}
}
