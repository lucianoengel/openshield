package main

import (
	"context"
	"strings"
	"testing"
)

// THE REFUSAL IS THE FEATURE.
//
// The file-open gate has no local fallback: whether a file carries sensitive content is the pipeline's
// judgement, so with OPENSHIELD_OPEN_GATE_DIRS set but no engine socket, the gate would fail open on every
// single event while logging itself as active. A gate that reports itself running and permits everything
// is worse than one that never started, because the second is visible.
//
// runOpenGate refuses that configuration before it opens anything, which is why this path needs no root
// and can be asserted here rather than only on the VM.
func TestTheOpenGateRefusesToStartWithoutAnEngineSocket(t *testing.T) {
	t.Setenv("OPENSHIELD_OPEN_GATE_DIRS", "/tmp/watched")
	t.Setenv("OPENSHIELD_OPEN_IPC_SOCKET", "")

	err := runOpenGate(context.Background())
	if err == nil {
		t.Fatal("the open gate started with no engine socket — it would fail open on every event while " +
			"reporting itself active")
	}
	// The message has to name the missing variable, because the operator's next action depends on it and
	// "could not start" sends them to the kernel logs instead of their unit file.
	if !strings.Contains(err.Error(), "OPENSHIELD_OPEN_IPC_SOCKET") {
		t.Fatalf("the refusal does not name the missing setting: %v", err)
	}

	// Whitespace is not a socket path. Trimming happens before the emptiness check, so " " must refuse
	// exactly as "" does rather than being carried forward as a path.
	//
	// ASSERTING ON THE MESSAGE, NOT MERELY ON err != nil, and the difference is the whole test. The first
	// version checked only that some error came back, and it passed against a mutant with TrimSpace
	// removed — because the gate then got PAST the config check and died at fanotify_init with "operation
	// not permitted". It was passing because this test runs unprivileged, not because whitespace was
	// rejected, and on the rooted VM it would have failed for a third unrelated reason. A test whose
	// verdict depends on which machine it runs on is not testing the code.
	t.Setenv("OPENSHIELD_OPEN_IPC_SOCKET", "   ")
	err = runOpenGate(context.Background())
	if err == nil {
		t.Fatal("a whitespace-only socket path was accepted as configuration")
	}
	if !strings.Contains(err.Error(), "OPENSHIELD_OPEN_IPC_SOCKET") {
		t.Fatalf("a whitespace-only socket path was carried forward as a real path; the gate failed later "+
			"for an unrelated reason instead of refusing the configuration: %v", err)
	}
}

func TestOpenGateConfiguredFollowsTheDirectoryList(t *testing.T) {
	for _, tc := range []struct {
		name string
		dirs string
		want bool
	}{
		{"unset", "", false},
		{"whitespace only", "   ", false},
		{"commas only", ",,,", false},
		{"one directory", "/var/data", true},
		{"several", "/var/data,/srv/files", true},
		{"padded", "  /var/data  ", true},
		// An entry that is only whitespace does not count, but a real one alongside it does.
		{"one real among blanks", " , /var/data , ", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OPENSHIELD_OPEN_GATE_DIRS", tc.dirs)
			if got := openGateConfigured(); got != tc.want {
				t.Fatalf("openGateConfigured() with dirs=%q = %v, want %v", tc.dirs, got, tc.want)
			}
		})
	}
}

func TestEnvInt(t *testing.T) {
	const key = "OPENSHIELD_TEST_INT"
	for _, tc := range []struct {
		name string
		set  bool
		val  string
		want int
	}{
		{"unset uses the default", false, "", 42},
		{"empty uses the default", true, "", 42},
		{"whitespace uses the default", true, "   ", 42},
		{"a number", true, "7", 7},
		{"padded number", true, "  7  ", 7},
		{"zero is a value, not absence", true, "0", 0},
		{"negative", true, "-3", -3},
		// A MALFORMED value falls back to the default rather than to zero. Zero would silently mean
		// "no budget"/"no limit" depending on the caller, and neither is what a typo asked for.
		{"not a number", true, "lots", 42},
		{"trailing junk", true, "7s", 42},
		{"float", true, "7.5", 42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(key, tc.val)
			}
			if got := envInt(key, 42); got != tc.want {
				t.Fatalf("envInt(%q, 42) = %d, want %d", tc.val, got, tc.want)
			}
		})
	}
}
