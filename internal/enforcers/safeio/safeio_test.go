package safeio_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/enforcers/safeio"
)

// 3.1 — ReadRegularNoFollow reads a regular file, but REFUSES a symlink (without
// reading its destination) and a non-regular target.
func TestReadRegularNoFollow(t *testing.T) {
	dir := t.TempDir()

	reg := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(reg, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := safeio.ReadRegularNoFollow(reg)
	if err != nil || !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("regular file: got (%q,%v), want (hello,nil)", got, err)
	}

	// A symlink to a secret must be REFUSED, and its destination NOT read.
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	data, err := safeio.ReadRegularNoFollow(link)
	if err == nil {
		t.Fatal("a symlink was followed and read")
	}
	if bytes.Contains(data, []byte("TOPSECRET")) {
		t.Fatal("the symlink's destination content was read")
	}

	// A directory is refused.
	if _, err := safeio.ReadRegularNoFollow(dir); err == nil {
		t.Error("a directory was accepted as a regular file")
	}
}

// RefuseNonRegular rejects a symlink and a non-regular target, accepts a regular.
func TestRefuseNonRegular(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "r")
	_ = os.WriteFile(reg, []byte("x"), 0o600)
	if err := safeio.RefuseNonRegular(reg); err != nil {
		t.Errorf("regular file refused: %v", err)
	}
	link := filepath.Join(dir, "l")
	_ = os.Symlink(reg, link)
	if err := safeio.RefuseNonRegular(link); err == nil {
		t.Error("a symlink was not refused")
	}
	if err := safeio.RefuseNonRegular(dir); err == nil {
		t.Error("a directory was not refused")
	}
}
