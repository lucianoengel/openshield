package gateway_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/casb"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
)

// casbPolicy blocks a flow only when the body is sensitive AND it is an upload to an
// UNSANCTIONED cloud service — the core CASB rule (content ∧ destination).
func casbPolicy(t *testing.T) core.Stage {
	t.Helper()
	pol, err := policy.New(context.Background(), "casb", "1", `package openshield
import rego.v1
sensitive if { some h in input.classification; h.count > 0 }
unsanctioned_upload if { input.event.cloud.upload; not input.event.cloud.sanctioned }
block if { sensitive; unsanctioned_upload }
decision := {"action":"BLOCK","reason":"sensitive content to an unsanctioned cloud service","confidence":0.9} if { block }
decision := {"action":"ALLOW","reason":"permitted","confidence":0.9} if { not block }`)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

// setCatalog installs a CASB catalog for the duration of a test (the catalog is a
// process-wide atomic, like exfil.Default). Tests here are serial (no t.Parallel).
func setCatalog(t *testing.T, text string) {
	t.Helper()
	c, err := casb.ParseCatalog(strings.NewReader(text))
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	casb.SetCatalog(c)
	t.Cleanup(func() { casb.SetCatalog(nil) })
}

// cloudReq builds a network request to a given host/method with a body.
func cloudReq(flowID, host, method, body string) *gateway.Request {
	return &gateway.Request{
		FlowID: flowID, SrcIP: "10.0.0.5", SrcPort: 44321,
		DstIP: "203.0.113.9", DstPort: 443, Protocol: "tcp",
		Host: host, Method: method, Path: "/upload",
		Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
		Body:      []byte(body),
	}
}

const casbCatalog = `service pastebin category paste
  host pastebin.com
service corpdrive category storage sanctioned
  host corpdrive.example.com
`

// startWorker starts the real worker subprocess (DLP classification of the body — no
// NIPS rules needed for CASB).
func startWorker(t *testing.T, bin string) *privileged.Worker {
	t.Helper()
	w, err := privileged.StartWorker(context.Background(), bin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

// TestSensitiveUploadToUnsanctionedCloudIsBlocked: a CPF body (classified by the REAL
// worker) POSTed to an UNSANCTIONED cloud service is blocked by the CASB rule.
//
// Mutation (casb.Classify returns nil): event.cloud is absent → unsanctioned_upload is
// false → the flow is ALLOWED → this test FAILs.
func TestSensitiveUploadToUnsanctionedCloudIsBlocked(t *testing.T) {
	setCatalog(t, casbCatalog)
	w := startWorker(t, buildWorkerBin(t))
	g := gateway.NewFromWorker(w, casbPolicy(t), &recLedger{}, nil, 10*time.Second)

	dec, err := g.Process(context.Background(), cloudReq("f-unsanc", "pastebin.com", "POST", cpfBody))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Fatalf("sensitive upload to an unsanctioned cloud = %v, want BLOCK", dec.GetAction())
	}
}

// TestSensitiveUploadToSanctionedCloudIsAllowed: the SAME CPF body to a SANCTIONED
// service is not blocked — the sanctioned flag gates.
//
// Mutation (Classify ignores the sanctioned flag / always false): the sanctioned host
// now looks unsanctioned → blocks → this test FAILs.
func TestSensitiveUploadToSanctionedCloudIsAllowed(t *testing.T) {
	setCatalog(t, casbCatalog)
	w := startWorker(t, buildWorkerBin(t))
	g := gateway.NewFromWorker(w, casbPolicy(t), &recLedger{}, nil, 10*time.Second)

	dec, err := g.Process(context.Background(), cloudReq("f-sanc", "corpdrive.example.com", "POST", cpfBody))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() == corev1.Action_ACTION_BLOCK {
		t.Fatalf("sensitive upload to a SANCTIONED cloud = BLOCK, want not-blocked (the sanctioned flag must gate)")
	}
}

// TestCleanUploadToUnsanctionedCloudNotBlocked: without sensitive content the rule does
// not fire even to an unsanctioned service (both conditions required).
func TestCleanUploadToUnsanctionedCloudNotBlocked(t *testing.T) {
	setCatalog(t, casbCatalog)
	w := startWorker(t, buildWorkerBin(t))
	g := gateway.NewFromWorker(w, casbPolicy(t), &recLedger{}, nil, 10*time.Second)

	dec, err := g.Process(context.Background(), cloudReq("f-clean", "pastebin.com", "POST", "an ordinary note, nothing sensitive"))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() == corev1.Action_ACTION_BLOCK {
		t.Fatalf("clean upload to an unsanctioned cloud = BLOCK, want not-blocked (needs sensitive content too)")
	}
}

// TestNonCloudFlowUnaffected: a sensitive POST to a non-cloud host carries no
// event.cloud, so the CASB rule cannot fire.
func TestNonCloudFlowUnaffected(t *testing.T) {
	setCatalog(t, casbCatalog)
	w := startWorker(t, buildWorkerBin(t))
	g := gateway.NewFromWorker(w, casbPolicy(t), &recLedger{}, nil, 10*time.Second)

	dec, err := g.Process(context.Background(), cloudReq("f-noncloud", "intranet.example.org", "POST", cpfBody))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() == corev1.Action_ACTION_BLOCK {
		t.Fatalf("sensitive POST to a non-cloud host = BLOCK, want not-blocked (no cloud channel)")
	}
}

// TestDownloadFromCloudIsNotUpload: a GET to an unsanctioned cloud host is not an upload,
// so the content+upload rule does not fire even with a sensitive body present.
//
// Mutation (Upload always true / ignore method): the GET now reads as an upload → blocks
// → this test FAILs.
func TestDownloadFromCloudIsNotUpload(t *testing.T) {
	setCatalog(t, casbCatalog)
	w := startWorker(t, buildWorkerBin(t))
	g := gateway.NewFromWorker(w, casbPolicy(t), &recLedger{}, nil, 10*time.Second)

	dec, err := g.Process(context.Background(), cloudReq("f-get", "pastebin.com", "GET", cpfBody))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() == corev1.Action_ACTION_BLOCK {
		t.Fatalf("GET (download) to a cloud host = BLOCK, want not-blocked (a download is not an upload)")
	}
}

// TestCasbCatalogHotReload: marking the unsanctioned service sanctioned in the catalog
// file at runtime makes a previously-blocked upload allowed, with no restart.
//
// Mutation (watcher never reloads / async baseline): the upload stays BLOCK → FAILs.
func TestCasbCatalogHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.txt")
	if err := os.WriteFile(path, []byte("service pastebin category paste\n  host pastebin.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := casb.LoadCatalog(path)
	if err != nil {
		t.Fatal(err)
	}
	casb.SetCatalog(cat)
	t.Cleanup(func() { casb.SetCatalog(nil) })

	watcher := casb.NewCatalogWatcher(path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Watch(ctx, 20*time.Millisecond,
		func(c *casb.Catalog) { casb.SetCatalog(c) },
		func(err error) { t.Error(err) })

	w := startWorker(t, buildWorkerBin(t))
	g := gateway.NewFromWorker(w, casbPolicy(t), &recLedger{}, nil, 10*time.Second)

	// Before the edit: unsanctioned → sensitive upload is blocked.
	dec, err := g.Process(context.Background(), cloudReq("f-pre", "pastebin.com", "POST", cpfBody))
	if err != nil {
		t.Fatal(err)
	}
	if dec.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Fatalf("pre-reload sensitive upload = %v, want BLOCK", dec.GetAction())
	}

	// Mark the service sanctioned and bump mtime.
	if err := os.WriteFile(path, []byte("service pastebin category paste sanctioned\n  host pastebin.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(6 * time.Second)
	for {
		dec, err := g.Process(context.Background(), cloudReq("f-post", "pastebin.com", "POST", cpfBody))
		if err != nil {
			t.Fatal(err)
		}
		if dec.GetAction() != corev1.Action_ACTION_BLOCK {
			return // the sanctioned edit took effect without a restart
		}
		if time.Now().After(deadline) {
			t.Fatal("the sanctioned edit never took effect — CASB hot-reload did not apply")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
