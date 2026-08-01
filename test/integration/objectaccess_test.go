//go:build integration

package integration

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// WHO CAN READ IT, against a REAL S3-compatible server (DSPM-2).
//
// The unit tests decide the ACL/policy/block-public-access logic against fixtures I wrote, so they can only
// prove the logic is self-consistent. What they cannot prove is that a real store, asked the way this code
// asks, answers in the shape this code parses — that the sub-resource query survives SigV4 signing, that
// MinIO's public-bucket policy actually comes back through `?policy`, and that a store which never
// implemented block-public-access does not blank the finding. Those are exactly the assumptions a fixture
// launders, so MinIO is the external anchor (D64) here as it is for the signature itself.
//
// The bucket is made public with MinIO's own client, not with this repository's code. If both sides used
// this signer and this policy encoder, a bug in either would cancel itself out.

// makeBucketPublic grants anonymous download on a bucket using MinIO's mc, which writes a real S3 bucket
// policy with `"Principal": {"AWS": ["*"]}`.
func makeBucketPublic(t *testing.T, endpoint, access, secret, bucket string) {
	t.Helper()
	args := []string{"run", "--rm", "--network=host", "--entrypoint", "/bin/sh", minioImage, "-c",
		fmt.Sprintf("mc alias set t %s %s %s >/dev/null && mc anonymous set download t/%s",
			endpoint, access, secret, bucket)}
	if out, err := exec.Command("podman", args...).CombinedOutput(); err != nil {
		t.Fatalf("making %s public: %v\n%s", bucket, err, out)
	}
}

// exposurePolicy alerts on the EXPOSURE ALONE, and the first version of this test did not.
//
// It read `exposure == PUBLIC AND a classifier hit`, which is the rule an operator actually wants — and it
// could not discriminate, because a custom policy COMPOSES with the observe-only default under
// most-restrictive-wins (ADR-5) and that default already ALERTs on a CPF wherever it finds one. Both buckets
// came back ALERT and the negative control proved nothing. That is a property of the composition, not a bug,
// and it is worth stating: a custom rule can only be OBSERVED to have fired when its outcome differs from
// what the default would have decided by itself.
//
// So the discriminator here is a BENIGN object, on which the default has no opinion. Only the bucket's
// exposure can move it.
const exposurePolicy = `package openshield
import rego.v1

decision := {"action": "ALERT", "reason": "an object sitting in a world-readable bucket"} if {
	input.event.object.exposure == "OBJECT_EXPOSURE_PUBLIC"
}
`

// TestBucketExposureIsDiscoveredAndRanksTheFinding is the DSPM-2 acceptance case.
//
// TWO SWEEPS OVER TWO BUCKETS HOLDING THE SAME SENSITIVE OBJECT. Everything is identical except who can read
// the bucket, so the difference in outcome can only have come from the exposure. Asserting on the public one
// alone would pass for a build that alerted on every discovered object, which is the failure this pairing
// exists to exclude.
func TestBucketExposureIsDiscoveredAndRanksTheFinding(t *testing.T) {
	endpoint, access, secret := startMinIO(t)
	const payroll, notes = "hr/payroll.csv", "public/notes.txt"
	sensitive := []byte("name,cpf\nalice,111.444.777-35\n")
	benign := []byte("nothing of interest in this file at all\n")

	for _, bucket := range []string{"exposed", "closed"} {
		putObject(t, endpoint, access, secret, bucket, payroll, sensitive)
		putObject(t, endpoint, access, secret, bucket, notes, benign)
	}
	makeBucketPublic(t, endpoint, access, secret, "exposed")

	// 1 = ACTION_ALLOW. Anything above it is a detection.
	sweep := func(t *testing.T, bucket string) (actions map[string]int, report string) {
		t.Helper()
		stack := StartStack(t)
		work := t.TempDir()
		polFile := filepath.Join(work, "exposure.rego")
		writeFile(t, polFile, []byte(exposurePolicy))

		eng := Start(t, "openshield-engine", []string{
			"OPENSHIELD_DSN=" + stack.DSN,
			"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
			"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
			"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
			"OPENSHIELD_POLICY_CUSTOM=" + polFile,
			"OPENSHIELD_OBJECT_ENDPOINT=" + endpoint,
			"OPENSHIELD_OBJECT_BUCKET=" + bucket,
			"OPENSHIELD_OBJECT_ACCESS_KEY=" + access,
			"OPENSHIELD_OBJECT_SECRET_KEY=" + secret,
			"OPENSHIELD_OBJECT_SWEEP_INTERVAL=5s",
		})
		eng.WaitForOutput("object discovery ACTIVE", 90*time.Second)

		pool := openPool(t, stack.DSN)
		actions = map[string]int{}
		action := func(key string) int {
			var a int
			if err := pool.QueryRow(Ctx(t),
				`SELECT coalesce(max(action),0) FROM audit_entries WHERE event_id = $1`,
				"objdisc-s3://"+bucket+"/"+key).Scan(&a); err != nil {
				t.Fatal(err)
			}
			return a
		}
		Eventually(t, 120*time.Second, "both objects in "+bucket+" to be swept and decided", func() bool {
			return action(payroll) > 0 && action(notes) > 0
		})
		actions[payroll], actions[notes] = action(payroll), action(notes)
		eng.WaitForOutput("object discovery sweep complete", 60*time.Second)
		return actions, eng.Output()
	}

	closed, closedReport := sweep(t, "closed")
	exposed, exposedReport := sweep(t, "exposed")

	// THE STORE ITSELF SAID SO. MinIO answers `?policy` with the anonymous-download policy mc wrote, and
	// this is the half no fixture can stand in for.
	if !contains(exposedReport, "exposure PUBLIC") {
		t.Errorf("the sweep of a world-readable bucket did not report it as PUBLIC — the probe is not "+
			"reaching the real store, or its answer is not being parsed\n%s", exposedReport)
	}
	if !contains(closedReport, "exposure PRIVATE") {
		t.Errorf("the sweep of a normal bucket did not report PRIVATE. A store that never implemented "+
			"block-public-access must not blank the determination — every S3-compatible deployment this "+
			"product targets is one\n%s", closedReport)
	}

	// AND THE EXPOSURE CROSSED THE WHOLE PIPELINE INTO A DECISION. The same benign object, byte for byte, in
	// two buckets: it is a finding in one and nothing in the other, and the only difference between them is
	// who can read the bucket.
	if exposed[notes] <= 1 {
		t.Errorf("a benign object in the world-readable bucket was decided action=%d, want a detection — "+
			"the exposure never reached the policy", exposed[notes])
	}
	if closed[notes] != 1 {
		t.Errorf("the same benign object in the closed bucket was decided action=%d, want ALLOW(1). A rule "+
			"that fires on every discovered object would satisfy the assertion above and mean nothing",
			closed[notes])
	}

	// THE CONTENT DETECTION IS UNAFFECTED IN BOTH. Exposure RANKS a finding; it does not replace one, and a
	// change that made the classifier's verdict depend on the bucket's ACL would be a serious regression
	// that the two assertions above would not notice.
	for name, got := range map[string]int{"exposed": exposed[payroll], "closed": closed[payroll]} {
		if got <= 1 {
			t.Errorf("the sensitive object in the %s bucket was decided action=%d, want a detection — "+
				"content classification must not depend on who can read the bucket", name, got)
		}
	}
}
