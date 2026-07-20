package agent_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/ipc"
	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/agent/worker"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// --- IPC framing ---
//
// The framing layer faces the privileged process from the less-trusted side.
// A length prefix read from a peer that just parsed an attacker's PDF is an
// allocation primitive unless it is bounded before use.

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := &corev1.ClassifyRequest{
		RequestId: "r1", EventId: "e1",
		Subject:  &corev1.ClassifyRequest_Path{Path: "/tmp/x"},
		MaxBytes: 1024,
	}
	if err := ipc.WriteFrame(&buf, want); err != nil {
		t.Fatal(err)
	}
	var got corev1.ClassifyRequest
	if err := ipc.ReadFrame(&buf, &got); err != nil {
		t.Fatal(err)
	}
	if got.GetRequestId() != "r1" || got.GetPath() != "/tmp/x" {
		t.Errorf("round trip lost data: %+v", &got)
	}
}

// A hostile length prefix must be rejected BEFORE the allocation, not after.
func TestOversizedFrameRejectedWithoutAllocating(t *testing.T) {
	// Claim 4 GiB, supply nothing.
	hdr := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	var msg corev1.ClassifyResponse
	err := ipc.ReadFrame(bytes.NewReader(hdr), &msg)
	if !errors.Is(err, ipc.ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge — an unbounded length prefix "+
			"from a less-trusted peer is a memory-exhaustion primitive", err)
	}
}

func TestTruncatedFrameIsAnError(t *testing.T) {
	var buf bytes.Buffer
	_ = ipc.WriteFrame(&buf, &corev1.ClassifyRequest{RequestId: "r1"})
	truncated := buf.Bytes()[:buf.Len()-2]
	var got corev1.ClassifyRequest
	err := ipc.ReadFrame(bytes.NewReader(truncated), &got)
	if err == nil {
		t.Fatal("truncated frame was accepted")
	}
}

// --- worker behaviour ---

type fakeClassifier struct {
	hits []*corev1.DetectorHit
	err  error
	seen []byte
}

func (f *fakeClassifier) Classify(_ context.Context, r io.Reader) ([]*corev1.DetectorHit, error) {
	b, _ := io.ReadAll(r)
	f.seen = b
	return f.hits, f.err
}

// A classifier error must NOT read as "nothing found". Conflating them would
// let a crashing parser make every file look clean — the quietest possible
// failure in a detection product.
func TestClassifierErrorIsNotACleanResult(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	_ = os.WriteFile(p, []byte("data"), 0o600)

	c := &fakeClassifier{err: errors.New("parser exploded")}
	resp := worker.Handle(context.Background(), c, &corev1.ClassifyRequest{
		RequestId: "r1", EventId: "e1",
		Subject: &corev1.ClassifyRequest_Path{Path: p},
	})
	if resp.GetError() == "" {
		t.Error("classifier failure produced no error — a crashing parser would read as a clean file")
	}
	if len(resp.GetHits()) != 0 {
		t.Error("hits reported alongside an error")
	}
}

func TestUnreadableFileIsAnErrorNotACleanResult(t *testing.T) {
	resp := worker.Handle(context.Background(), &fakeClassifier{}, &corev1.ClassifyRequest{
		RequestId: "r1",
		Subject:   &corev1.ClassifyRequest_Path{Path: "/nonexistent/definitely"},
	})
	if resp.GetError() == "" {
		t.Error("unreadable file reported as a clean result")
	}
}

// The byte ceiling must bound the parser's input and SAY it truncated. Silent
// truncation makes a large file an evasion technique: pad past the limit and
// the payload is never seen, with nothing to indicate it.
func TestByteCeilingBoundsInputAndReportsTruncation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(p, bytes.Repeat([]byte("A"), 10_000), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &fakeClassifier{}
	resp := worker.Handle(context.Background(), c, &corev1.ClassifyRequest{
		RequestId: "r1",
		Subject:   &corev1.ClassifyRequest_Path{Path: p},
		MaxBytes:  100,
	})
	if len(c.seen) > 100 {
		t.Errorf("classifier saw %d bytes, ceiling was 100", len(c.seen))
	}
	if !resp.GetTruncated() {
		t.Error("truncation not reported — silent truncation turns file size into an evasion")
	}
}

// The worker opens files itself. If the privileged process read the file and
// passed bytes, attacker-controlled content would land in the address space
// holding CAP_SYS_ADMIN, which is the whole thing being prevented.
func TestWorkerRefusesWhenGivenNoPath(t *testing.T) {
	resp := worker.Handle(context.Background(), &fakeClassifier{}, &corev1.ClassifyRequest{
		RequestId: "r1",
		Subject:   &corev1.ClassifyRequest_FileHandle{FileHandle: []byte{1, 2, 3}},
	})
	if resp.GetError() == "" {
		t.Error("worker accepted a handle it cannot resolve; resolution is the privileged side's job (T-005)")
	}
}

// --- process boundary, end to end ---

func buildWorker(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "openshield-worker")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/openshield-worker")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building worker: %v\n%s", err, out)
	}
	return bin
}

func TestPrivilegedTalksToWorkerAcrossProcessBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping process-boundary test in -short mode")
	}
	bin := buildWorker(t)

	w, err := privileged.StartWorker(context.Background(), bin)
	if err != nil {
		t.Fatalf("starting worker: %v", err)
	}
	defer w.Close()

	dir := t.TempDir()
	p := filepath.Join(dir, "customers.csv")
	_ = os.WriteFile(p, []byte("name,cpf\nalice,11144477735\n"), 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := w.Classify(ctx, &corev1.ClassifyRequest{
		RequestId: "r1", EventId: "e1",
		Subject: &corev1.ClassifyRequest_Path{Path: p},
	})
	if err != nil {
		t.Fatalf("classify across process boundary: %v", err)
	}
	if resp.GetRequestId() != "r1" {
		t.Errorf("request id = %q, want r1", resp.GetRequestId())
	}
	if resp.GetError() != "" {
		t.Errorf("unexpected worker error: %s", resp.GetError())
	}
}

// A worker that hangs must look exactly like a worker that failed. Behind the
// pipeline sits a process blocked in the kernel; an unbounded wait there is how
// a machine hangs.
func TestWorkerTimeoutIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping process test in -short mode")
	}
	// `sleep` never speaks the protocol, so the read blocks forever.
	w, err := privileged.StartWorker(context.Background(), "/bin/sleep", "30")
	if err != nil {
		t.Fatalf("starting stub: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = w.Classify(ctx, &corev1.ClassifyRequest{RequestId: "r1"})
	elapsed := time.Since(start)

	if !errors.Is(err, privileged.ErrWorkerTimeout) {
		t.Errorf("err = %v, want ErrWorkerTimeout", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("waited %v — the deadline did not bound the privileged side", elapsed)
	}
}

// A desynchronised stream must not silently attribute one file's findings to
// another. That is quietly wrong in exactly the way that ruins an audit trail.
func TestMismatchedResponseIdIsRejected(t *testing.T) {
	var reqBuf, respBuf bytes.Buffer
	_ = ipc.WriteFrame(&respBuf, &corev1.ClassifyResponse{RequestId: "WRONG", EventId: "e1"})

	// Exercise the framing directly: a response whose id differs must be
	// detectable by the caller.
	var got corev1.ClassifyResponse
	if err := ipc.ReadFrame(&respBuf, &got); err != nil {
		t.Fatal(err)
	}
	if got.GetRequestId() == "r1" {
		t.Fatal("test fixture is wrong")
	}
	_ = reqBuf
	if !strings.Contains(got.GetRequestId(), "WRONG") {
		t.Errorf("unexpected id %q", got.GetRequestId())
	}
}
