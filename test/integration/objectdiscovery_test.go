//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// DATA AT REST, against a REAL S3-compatible server (DSPM-1).
//
// The signature is why this cannot be a unit test. SigV4 is hand-rolled here — twelve direct dependencies
// are worth protecting and the AWS SDK is dozens of modules for two REST calls — and a unit test that
// recomputed the expected signature with the same code under test would agree with whatever that code
// believes. That is this project's signature failure mode. A real server is the external anchor (D64): a
// wrong signature is a 403 and nothing else works.
//
// MinIO speaks the same API as S3, Ceph, R2 and Wasabi, so this also demonstrates the thing that made
// hand-rolling worthwhile — the connector is not AWS-specific, and for a self-hostable product the
// self-hosted store is arguably the more relevant target.

const minioImage = "docker.io/minio/minio:latest"

// startMinIO brings up a MinIO and returns its endpoint and credentials.
func startMinIO(t *testing.T) (endpoint, access, secret string) {
	t.Helper()
	requirePodman(t)
	access, secret = "openshieldtest", "openshieldtestsecret"
	name := uniqueName(t, "minio")
	port := freePort(t)
	run(t, "podman", "run", "-d", "--rm", "--name", name,
		"-e", "MINIO_ROOT_USER="+access,
		"-e", "MINIO_ROOT_PASSWORD="+secret,
		"-p", "127.0.0.1:"+port+":9000",
		minioImage, "server", "/data")
	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", name).Run() })
	endpoint = "http://127.0.0.1:" + port
	waitTCP(t, "127.0.0.1:"+port, 90*time.Second)
	// A listening port is not a ready server: MinIO answers TCP before it will serve the API.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(endpoint + "/minio/health/live")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return endpoint, access, secret
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("minio did not become ready at %s", endpoint)
	return "", "", ""
}

// putObject uploads one object using the MinIO client inside the container's own image, so the test's
// upload path does not share code with the connector's download path. If both used this repository's
// signer, a signing bug would cancel itself out and the test would pass against a broken client.
func putObject(t *testing.T, endpoint, access, secret, bucket, key string, body []byte) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "payload")
	writeFile(t, tmp, body)
	args := []string{"run", "--rm", "--network=host",
		"-v", tmp + ":/payload:ro,Z",
		"--entrypoint", "/bin/sh", minioImage, "-c",
		fmt.Sprintf("mc alias set t %s %s %s >/dev/null && mc mb -p t/%s >/dev/null && mc cp /payload t/%s/%s >/dev/null",
			endpoint, access, secret, bucket, bucket, key)}
	if out, err := exec.Command("podman", args...).CombinedOutput(); err != nil {
		t.Fatalf("uploading %s: %v\n%s", key, err, out)
	}
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSensitiveDataAtRestIsDiscovered is the DSPM-1 acceptance case.
//
// Three objects, and the second and third are what make the first mean something:
//
//   - sensitive within the prefix ceiling — must be found;
//   - sensitive only PAST the ceiling — must NOT be found, because that is the documented limit and a test
//     that ignored it would let the ceiling be believed unlimited;
//   - benign — must not be found, because a detector that fires on everything is a queue nobody reads.
func TestSensitiveDataAtRestIsDiscovered(t *testing.T) {
	stack := StartStack(t)
	endpoint, access, secret := startMinIO(t)
	work := t.TempDir()
	const bucket = "discovery"

	// Within the ceiling.
	putObject(t, endpoint, access, secret, bucket, "hr/payroll.csv",
		[]byte("name,cpf\nalice,111.444.777-35\n"))
	// Sensitive only PAST the ceiling: padding first, then the CPF.
	past := append(bytes.Repeat([]byte("x"), 40<<10), []byte("\ncpf: 111.444.777-35\n")...)
	putObject(t, endpoint, access, secret, bucket, "hr/archive.txt", past)
	// Benign.
	putObject(t, endpoint, access, secret, bucket, "public/readme.txt",
		[]byte("nothing of interest in this file at all\n"))

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(), // the engine requires at least one
		"OPENSHIELD_OBJECT_ENDPOINT=" + endpoint,
		"OPENSHIELD_OBJECT_BUCKET=" + bucket,
		"OPENSHIELD_OBJECT_ACCESS_KEY=" + access,
		"OPENSHIELD_OBJECT_SECRET_KEY=" + secret,
		"OPENSHIELD_OBJECT_MAX_BYTES=" + strconv.Itoa(16<<10), // below the padding, so the ceiling bites
		"OPENSHIELD_OBJECT_SWEEP_INTERVAL=5s",
	})
	eng.WaitForOutput("object discovery ACTIVE", 90*time.Second)

	pool := openPool(t, stack.DSN)
	// ASSERTED ON THE ACTION, NOT ON A ROW EXISTING. The first version of this test only checked that an
	// audit row appeared for the object, which would have passed with classification switched off entirely —
	// the sweep discovers, a decision is recorded, and nothing ever looked inside. "It reached the ledger"
	// is not "its content was examined", and only the second is the feature.
	// 1 = ACTION_ALLOW; anything higher is a detection.
	action := func(key string) int {
		var a int
		if err := pool.QueryRow(Ctx(t),
			`SELECT coalesce(max(action),0) FROM audit_entries WHERE event_id = $1`,
			"objdisc-s3://"+bucket+"/"+key).Scan(&a); err != nil {
			t.Fatal(err)
		}
		return a
	}

	// THE OBJECT WITHIN THE CEILING IS DETECTED. This is the whole feature: nobody touched this file, and
	// the product knows the sensitive data is in it.
	Eventually(t, 120*time.Second, "the payroll object's CONTENT to be classified and acted on", func() bool {
		return action("hr/payroll.csv") > 1
	})

	// The benign object was swept too, so the negatives below are meaningful rather than merely early.
	Eventually(t, 60*time.Second, "the whole bucket to have been swept", func() bool {
		return action("public/readme.txt") > 0
	})

	// AND THE BENIGN ONE DID NOT FIRE. A detector that alerts on everything is a queue nobody reads, and it
	// would satisfy the assertion above.
	if a := action("public/readme.txt"); a > 1 {
		t.Errorf("a benign object was flagged (action=%d) — a sweep that fires on everything is not a "+
			"discovery feature, it is noise with a bucket name attached", a)
	}

	// THE CEILING IS A REAL LIMIT, and this pins the documented behaviour rather than an aspiration. The
	// object IS discovered — it exists, and the sweep says so — but its sensitive content sits past the
	// prefix and is not seen. Without this, "we scan your buckets" reads as "we scan all of every object".
	if a := action("hr/archive.txt"); a > 1 {
		t.Errorf("content PAST the %d-byte prefix ceiling was detected (action=%d). Either the ceiling is not "+
			"being applied, or this test no longer pins the documented limit", 16<<10, a)
	}

	// AND THE SWEEP REPORTED ITS COVERAGE, every time, not only when it skipped something.
	if !contains(eng.Output(), "object discovery sweep complete") {
		t.Errorf("no coverage report after a sweep — a clean discovery result an operator cannot size is "+
			"an assertion about what is NOT there with nothing behind it\n%s", eng.Output())
	}
}
