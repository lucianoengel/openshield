package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// TestWorkerLoadsEDMIndexAndMatches (R34 test proposal #12 — DLP-3's last untested link): the REAL
// openshield-worker binary, given OPENSHIELD_EDM_INDEX pointing at a Marshal'd index, loads it and
// reports a DETECTOR_TYPE_EDM hit for a file containing a seeded value — over the real RPC/stdin path,
// not an in-process classifier. This closes the gap between "the EDM index/detector are unit-tested"
// and "the shipped worker actually loads and uses one".
func TestWorkerLoadsEDMIndexAndMatches(t *testing.T) {
	// A k-anonymized EDM index over a distinctive seeded value.
	const secret = "ACCT-00099812-XZ"
	idx := classify.NewEDMIndex(0.001, 8)
	idx.Add(secret)
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "edm.idx")
	if err := os.WriteFile(indexPath, idx.Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	// The worker reads OPENSHIELD_EDM_INDEX from its environment; the child inherits ours. No
	// OPENSHIELD_DLP_INDEX_PUBKEY → the worker loads it unsigned (with a warning), which is fine here.
	t.Setenv("OPENSHIELD_EDM_INDEX", indexPath)

	ctx := context.Background()
	worker, err := privileged.StartWorker(ctx, buildWorker(t))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	// A file whose content contains the seeded value.
	file := filepath.Join(dir, "leak.csv")
	if err := os.WriteFile(file, []byte("id,account\n42,"+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := worker.Classify(cctx, &corev1.ClassifyRequest{
		RequestId: "r1", EventId: "e1",
		Subject: &corev1.ClassifyRequest_Path{Path: file},
	})
	if err != nil {
		t.Fatalf("worker classify: %v", err)
	}
	if resp.GetError() != "" {
		t.Fatalf("worker reported an error: %s", resp.GetError())
	}
	sawEDM := false
	for _, h := range resp.GetHits() {
		if h.GetDetectorType() == corev1.DetectorType_DETECTOR_TYPE_EDM {
			sawEDM = true
		}
	}
	if !sawEDM {
		t.Fatalf("the real worker did not report an EDM hit for a seeded value (hits: %v) — the shipped OPENSHIELD_EDM_INDEX path is unverified", resp.GetHits())
	}

	// Control: a file WITHOUT the seeded value produces no EDM hit (the index is not matching everything).
	clean := filepath.Join(dir, "clean.csv")
	if err := os.WriteFile(clean, []byte("id,account\n42,NOT-A-SEEDED-VALUE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp2, err := worker.Classify(cctx, &corev1.ClassifyRequest{
		RequestId: "r2", EventId: "e2",
		Subject: &corev1.ClassifyRequest_Path{Path: clean},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range resp2.GetHits() {
		if h.GetDetectorType() == corev1.DetectorType_DETECTOR_TYPE_EDM {
			t.Fatalf("the worker reported an EDM hit for a file with no seeded value — the index matches too broadly")
		}
	}
}
