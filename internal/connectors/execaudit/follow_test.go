package execaudit

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// readWithin reads until it sees want or the deadline passes. The follower blocks by design, so a
// plain Read would hang the test rather than fail it.
func readWithin(t *testing.T, r io.Reader, want string, d time.Duration) string {
	t.Helper()
	type res struct {
		s   string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		var got []byte
		buf := make([]byte, 256)
		for {
			n, err := r.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				ch <- res{string(got), err}
				return
			}
			if want != "" && len(got) > 0 && contains(string(got), want) {
				ch <- res{string(got), nil}
				return
			}
		}
	}()
	select {
	case v := <-ch:
		return v.s
	case <-time.After(d):
		t.Fatalf("timed out waiting to read %q", want)
		return ""
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

// TestFollowReturnsBytesAppendedAfterOpen is the defect this exists for: the connector used to stop
// at EOF, so an execution recorded after startup was never seen.
func TestFollowReturnsBytesAppendedAfterOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := Follow(ctx, f, path, 20*time.Millisecond)

	// APPENDED AFTER the reader exists — writing it first would pass against the old behaviour, which
	// is exactly how this defect survived.
	go func() {
		time.Sleep(50 * time.Millisecond)
		af, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		_, _ = af.WriteString("appended-after-start\n")
		_ = af.Close()
	}()

	got := readWithin(t, r, "appended-after-start", 5*time.Second)
	if !contains(got, "first") {
		t.Errorf("the existing content was not read: %q", got)
	}
}

// TestFollowResumesAfterTruncation: `> file` and copy-truncate rotators leave a shorter file whose
// content is new. Continuing from the old offset would skip it silently.
func TestFollowResumesAfterTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("aaaaaaaaaaaaaaaaaaaa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := Follow(ctx, f, path, 20*time.Millisecond)
	readWithin(t, r, "aaaa", 5*time.Second)

	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = os.WriteFile(path, []byte("after-truncate\n"), 0o600)
	}()
	got := readWithin(t, r, "after-truncate", 5*time.Second)
	if !contains(got, "after-truncate") {
		t.Errorf("content written after truncation was not read: %q", got)
	}
}

// TestFollowReopensAReplacedFile: the rename-and-recreate rotation, where the old handle stays valid
// and permanently empty — the failure that looks most like "the estate went quiet".
func TestFollowReopensAReplacedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("before-rotate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := Follow(ctx, f, path, 20*time.Millisecond)
	readWithin(t, r, "before-rotate", 5*time.Second)

	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = os.Rename(path, filepath.Join(dir, "audit.log.1"))
		_ = os.WriteFile(path, []byte("after-rotate\n"), 0o600)
	}()
	got := readWithin(t, r, "after-rotate", 5*time.Second)
	if !contains(got, "after-rotate") {
		t.Errorf("content in the replacement file was not read: %q", got)
	}
}

// TestFollowEndsOnContextCancel — the ONLY condition under which it reports EOF, so the scanner's loop
// ends on shutdown and at no other time.
func TestFollowEndsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	r := Follow(ctx, f, path, 20*time.Millisecond)

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := r.Read(buf)
		done <- err
	}()
	time.Sleep(60 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("the follower returned %v on an idle file; it must WAIT, or the connector stops at "+
			"EOF exactly as it did before", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Errorf("after cancellation the follower returned %v, want io.EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the follower did not end after its context was cancelled — shutdown would hang")
	}
}
