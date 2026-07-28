//go:build integration

package integration

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// THE CASB CATALOG, AS THE GATEWAY ACTUALLY LOADS IT (DLP-2).
//
// `internal/gateway` already tests the CASB rule thoroughly — but it does so by calling
// `casb.SetCatalog` directly. That leaves the whole of `OPENSHIELD_CASB_CATALOG` untested: the env
// read, the parse, the process-wide install, and the hot-reload loop. Every one of those could be
// wrong and the package tests would stay green, because they never go through them. That is the exact
// shape of the six defects catalogued in docs/unwired-audit.md — a capability with a test and no
// caller.
//
// So these run the real binary with the real setting, and assert on what the UPSTREAM received.

// casbCatalogText is the operator catalog these scenarios drive. The destination hosts are LOOPBACK
// ADDRESSES rather than domain names, because the gateway resolves the destination itself and this
// suite has no DNS it controls. The domain-suffix semantics (drive.example.com matching a
// sub.drive.example.com upload) are the parser's business and are covered in the casb package; what
// is under test here is that the file reaches the running process at all.
func casbCatalogText(unsanctioned, sanctioned string) string {
	return "service pastewall category paste\n  host " + unsanctioned +
		"\nservice corpdrive category storage sanctioned\n  host " + sanctioned + "\n"
}

// casbGatewayPolicy is the CASB rule proper: sensitive content AND an upload to a service the
// operator has NOT sanctioned. Both halves matter — a policy that blocked on content alone would
// pass a catalog test while telling us nothing about the catalog.
const casbGatewayPolicy = `package openshield
import rego.v1
sensitive if { some h in input.classification; h.count > 0 }
unsanctioned_upload if { input.event.cloud.upload; not input.event.cloud.sanctioned }
decision := {"action":"BLOCK","reason":"sensitive content to an unsanctioned cloud service"} if { sensitive; unsanctioned_upload }
decision := {"action":"ALLOW","reason":"permitted"} if { not sensitive }
decision := {"action":"ALLOW","reason":"sanctioned destination"} if { sensitive; not unsanctioned_upload }`

// postThrough uploads a sensitive body through the proxy to a destination and returns the status.
func postThrough(t *testing.T, gatewayAddr, dest string) int {
	t.Helper()
	resp, err := proxyClient(t, gatewayAddr).Post("http://"+dest+"/upload", "text/csv", strings.NewReader(cpfBody))
	if err != nil {
		t.Fatalf("proxying an upload to %s: %v", dest, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestTheGatewayLoadsItsCasbCatalogFromTheConfiguredFile.
//
// The two halves are what make this about the CATALOG rather than about DLP:
//
//   - the UNSANCTIONED destination is blocked — with no catalog loaded there is no `input.event.cloud`
//     at all, so nothing would block and this half fails;
//   - the SANCTIONED destination is allowed — a catalog that parsed but dropped the `sanctioned`
//     flag would block both, and this half fails.
//
// Neither is satisfiable by a gateway that merely started up cleanly.
func TestTheGatewayLoadsItsCasbCatalogFromTheConfiguredFile(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	unsanctioned, unsanctionedHits := startCloudUpstream(t, "127.0.0.2")
	sanctioned, sanctionedHits := startCloudUpstream(t, "127.0.0.3")

	catalog := filepath.Join(work, "cloud.catalog")
	if err := os.WriteFile(catalog, []byte(casbCatalogText("127.0.0.2", "127.0.0.3")), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(work, "casb.rego")
	if err := os.WriteFile(policy, []byte(casbGatewayPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	gw, addr := startGateway(t, stack,
		"OPENSHIELD_CASB_CATALOG="+catalog,
		"OPENSHIELD_POLICY_CUSTOM="+policy,
		"OPENSHIELD_ENFORCE=1")
	gw.WaitForOutput("content-aware CASB active", 60*time.Second)

	if code := postThrough(t, addr, unsanctioned); code != http.StatusForbidden {
		t.Fatalf("a sensitive upload to an UNSANCTIONED catalogued service returned %d, want 403 — with no "+
			"catalog in the running process there is no cloud subject in the policy input, and a CASB rule "+
			"that can never fire is a feature the operator believes they configured\n%s", code, gw.Output())
	}
	if n := unsanctionedHits.Load(); n != 0 {
		t.Errorf("the unsanctioned upstream received %d request(s) — a 403 to the client is not prevention "+
			"if the body left anyway", n)
	}

	if code := postThrough(t, addr, sanctioned); code != http.StatusOK {
		t.Fatalf("the SAME sensitive body to a SANCTIONED service returned %d, want 200. CASB's whole point "+
			"is that the destination decides; blocking both is a content rule wearing a catalog\n%s",
			code, gw.Output())
	}
	if n := sanctionedHits.Load(); n != 1 {
		t.Errorf("the sanctioned upstream received %d requests, want 1", n)
	}
}

// TestACatalogChangeTakesEffectAndABadEditDoesNot is the hot-reload contract
// (OPENSHIELD_CASB_CATALOG_RELOAD), which is a conjunction of two opposed properties.
//
// THE ORDER OF THE THREE STEPS IS THE TEST. Starting sanctioned and then withdrawing sanction means
// each step asserts in the direction an empty catalog CANNOT satisfy:
//
//  1. sanctioned → allowed (the baseline);
//  2. edited to unsanctioned → blocked. This proves the reload actually reloaded; a watcher that never
//     ticked would leave step 1's answer in place.
//  3. edited to GARBAGE → still blocked. A bad edit must never disarm the running engine, and if the
//     reload installed an empty catalog on a parse error the flow would go back to being ALLOWED.
//
// Written the other way round — start unsanctioned, then break the file, then assert "still blocked" —
// step 3 would be vacuous: an emptied catalog also yields "not blocked", so the assertion would pass
// for the wrong reason. That is the fifth way a green test can mean nothing.
func TestACatalogChangeTakesEffectAndABadEditDoesNot(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	dest, hits := startCloudUpstream(t, "127.0.0.2")

	catalog := filepath.Join(work, "cloud.catalog")
	write := func(text string) {
		t.Helper()
		if err := os.WriteFile(catalog, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// 127.0.0.2 starts out SANCTIONED.
	write("service corpdrive category storage sanctioned\n  host 127.0.0.2\n")
	policy := filepath.Join(work, "casb.rego")
	if err := os.WriteFile(policy, []byte(casbGatewayPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	gw, addr := startGateway(t, stack,
		"OPENSHIELD_CASB_CATALOG="+catalog,
		"OPENSHIELD_CASB_CATALOG_RELOAD=1s",
		"OPENSHIELD_POLICY_CUSTOM="+policy,
		"OPENSHIELD_ENFORCE=1")
	gw.WaitForOutput("CASB catalog hot-reload enabled", 60*time.Second)

	if code := postThrough(t, addr, dest); code != http.StatusOK {
		t.Fatalf("step 1: a sanctioned destination returned %d, want 200\n%s", code, gw.Output())
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("step 1: the upstream received %d requests, want 1", n)
	}

	// 2. The operator WITHDRAWS sanction. No restart.
	write("service corpdrive category storage\n  host 127.0.0.2\n")
	gw.WaitForOutput("CASB catalog reloaded", 60*time.Second)
	if code := postThrough(t, addr, dest); code != http.StatusForbidden {
		t.Fatalf("step 2: after sanction was WITHDRAWN the upload returned %d, want 403. A catalog that "+
			"only takes effect at restart means every policy change waits for a maintenance window\n%s",
			code, gw.Output())
	}

	// 3. A typo. The running catalog must survive it.
	write("service corpdrive category storage\n  hosts 127.0.0.2\n")
	gw.WaitForOutput("CASB catalog reload failed", 60*time.Second)
	if code := postThrough(t, addr, dest); code != http.StatusForbidden {
		t.Fatalf("step 3: after a MALFORMED edit the upload returned %d, want 403 — the previous catalog "+
			"must be kept. A parse error that empties the catalog turns one operator typo into a silent, "+
			"fleet-wide loss of cloud-upload control\n%s", code, gw.Output())
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("the upstream received %d requests, want 1 — only step 1 should ever have reached it", n)
	}
}

// startCloudUpstream runs an origin on a SPECIFIC loopback IP and returns both its address and its
// hit counter.
//
// Two addresses are needed because the catalog identifies a service by HOST, and a port is stripped
// before matching — two ports of 127.0.0.1 would be one service, which is precisely the distinction
// these scenarios exist to draw. 127.0.0.2 and 127.0.0.3 are ordinary loopback addresses: Linux
// routes all of 127/8 locally, so this needs no interface setup and no privilege.
func startCloudUpstream(t *testing.T, ip string) (addr string, hits *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatalf("listening on %s: %v", ip, err)
	}
	var n atomic.Int64
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		_, _ = w.Write([]byte("origin-ok"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), &n
}
