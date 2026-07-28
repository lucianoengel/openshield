package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE UNIX ADDRESS LIMIT, CAUGHT AT CONFIGURATION TIME (D325).
//
// A `sockaddr_un` holds 108 bytes on Linux and 104 on macOS, and the kernel does not truncate an
// over-long address — it refuses the bind with EINVAL, surfaced as "bind: invalid argument". That names
// neither the length nor the cause.
//
// The shape of the failure is what makes this worth catching in configuration rather than at the
// listener. The engine validates its configuration, starts the verdict server, logs "exec-verdict IPC
// ACTIVE", and only then fails to listen — so the operator has a process that SAID the feature was on.
// The privileged gate, unable to reach a socket that was never bound, degrades to its static path and
// fails open with an audit per exec, exactly as designed. Every component behaves correctly, the
// deployment does not work, and nothing names the cause.

func socketField() Field {
	return Field{Key: "OPENSHIELD_TEST_SOCKET", Scope: ScopeBootstrap, Kind: KindSocketPath}
}

// TestAnOverLongSocketPathIsRefusedWithItsLength.
//
// The message must carry the LENGTH. "Path too long" sends an operator to trim a directory name by
// guesswork; the number tells them how much has to go.
func TestAnOverLongSocketPathIsRefusedWithItsLength(t *testing.T) {
	dir := t.TempDir()
	long := filepath.Join(dir, strings.Repeat("a", MaxSocketPath)+".sock")

	err := parseForOrigin(socketField(), long, "env")
	if err == nil {
		t.Fatalf("a %d-byte socket path was accepted against a %d-byte limit — the bind will fail with "+
			"EINVAL and the operator will be told nothing useful", len(long), MaxSocketPath)
	}
	if !strings.Contains(err.Error(), "socket path is") || !strings.Contains(err.Error(), "over this platform's") {
		t.Errorf("the refusal does not state the length and the limit, so it is no more useful than the "+
			"kernel's own message: %v", err)
	}
}

// TestASocketPathWithinTheLimitIsAccepted, including one that does not exist yet — which is every socket
// before its server starts.
func TestASocketPathWithinTheLimitIsAccepted(t *testing.T) {
	dir, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	p := filepath.Join(dir, "v.sock")
	if len(p) > MaxSocketPath {
		t.Skipf("the test's own temp path is already %d bytes; nothing to prove here", len(p))
	}
	if err := parseForOrigin(socketField(), p, "env"); err != nil {
		t.Errorf("a %d-byte socket path was refused against a %d-byte limit: %v", len(p), MaxSocketPath, err)
	}
}

// TestASocketPathKeepsTheParentDirectoryCheck. The length bound is ADDITIONAL; losing the parent check
// while adding it would trade one silent misconfiguration for another.
func TestASocketPathKeepsTheParentDirectoryCheck(t *testing.T) {
	// Built from os.MkdirTemp rather than t.TempDir even though nothing here BINDS — the fitness guard
	// forbids the idiom outright, and an exemption for "this one is only validated, not bound" would
	// need the guard to reason about intent. Keeping the rule absolute is cheaper than teaching it.
	dir, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "no-such-dir", "v.sock")
	refusal := parseForOrigin(socketField(), p, "env")
	if refusal == nil {
		t.Fatal("a socket path whose parent directory does not exist was accepted")
	}
	if !strings.Contains(refusal.Error(), "parent directory") {
		t.Errorf("the refusal does not name the missing directory: %v", refusal)
	}
}

// TestTheLimitIsThisPlatformsNotThePortableMinimum.
//
// Validating against 104 everywhere would be simpler and would give one number in one message. It is
// wrong: a 106-byte path binds correctly on Linux, and refusing it would be rejecting VALID
// configuration — which leaves the operator with a correct value the product will not take, and no
// recourse. Refusing what works is a worse failure than a message that differs by platform.
func TestTheLimitIsThisPlatformsNotThePortableMinimum(t *testing.T) {
	const linuxLimit, portableMinimum = 108, 104
	if MaxSocketPath != linuxLimit && MaxSocketPath != portableMinimum {
		t.Fatalf("MaxSocketPath is %d, which is neither this platform's limit nor the portable "+
			"minimum — one of the two constants is wrong", MaxSocketPath)
	}
	// On the ship target the limit must be the real one, not the conservative cross-platform figure.
	if isLinux() && MaxSocketPath != linuxLimit {
		t.Errorf("on Linux the limit is %d, not %d — validating against the portable minimum would "+
			"refuse a path the kernel accepts", linuxLimit, MaxSocketPath)
	}
}
