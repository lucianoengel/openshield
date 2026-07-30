package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readRoster(t *testing.T, path string) []string {
	t.Helper()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading roster: %v", err)
	}
	var out []string
	for _, l := range strings.Split(string(blob), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func agentsIn(t *testing.T, path string) []string {
	t.Helper()
	var ids []string
	for _, l := range readRoster(t, path) {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		ids = append(ids, strings.Fields(l)[0])
	}
	return ids
}

func enroll(t *testing.T, roster, agent string) string {
	t.Helper()
	out := t.TempDir()
	if code := run([]string{"posture-enroll", "--agent", agent, "--roster", roster, "--out", out}); code != 0 {
		t.Fatalf("posture-enroll %s exited %d", agent, code)
	}
	return out
}

func TestEnrollingAnAgentWritesARosterLineAndAPrivateKey(t *testing.T) {
	roster := filepath.Join(t.TempDir(), "roster")
	out := enroll(t, roster, "laptop-01")

	lines := readRoster(t, roster)
	if len(lines) != 1 {
		t.Fatalf("roster has %d lines, want 1: %v", len(lines), lines)
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 2 || fields[0] != "laptop-01" {
		t.Fatalf("roster line %q is not '<agent> <base64key>'", lines[0])
	}
	// The gateway base64-decodes this; a line it cannot decode aborts its startup.
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		t.Fatalf("the roster's public key is not valid base64: %v", err)
	}

	fi, err := os.Stat(filepath.Join(out, "posture-priv"))
	if err != nil {
		t.Fatalf("posture-priv was not written: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("posture-priv is mode %04o — the key that lets this agent make a believed posture claim, "+
			"readable by group or other", perm)
	}
}

// A fleet is enrolled one machine at a time. A command that truncated the roster would silently unenrol
// every other agent, and because unenrolled posture is never applied, the symptom would be "the fleet lost
// its posture signal after we added a laptop".
func TestEnrollingASecondAgentKeepsTheFirst(t *testing.T) {
	roster := filepath.Join(t.TempDir(), "roster")
	enroll(t, roster, "laptop-01")
	enroll(t, roster, "laptop-02")
	enroll(t, roster, "laptop-03")

	got := agentsIn(t, roster)
	want := []string{"laptop-01", "laptop-02", "laptop-03"}
	if len(got) != len(want) {
		t.Fatalf("roster holds %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("roster holds %v, want %v", got, want)
		}
	}
}

// Two lines for one agent means the loader picks whichever it saw last — a key rotation that half worked,
// which is worse than one that failed outright.
func TestReEnrollingAnAgentReplacesItsLineRatherThanAddingASecond(t *testing.T) {
	roster := filepath.Join(t.TempDir(), "roster")
	enroll(t, roster, "laptop-01")
	first := readRoster(t, roster)[0]

	enroll(t, roster, "laptop-02")
	enroll(t, roster, "laptop-01") // rotate laptop-01's key

	ids := agentsIn(t, roster)
	seen := map[string]int{}
	for _, id := range ids {
		seen[id]++
	}
	if seen["laptop-01"] != 1 {
		t.Fatalf("laptop-01 appears %d times after re-enrolment: %v", seen["laptop-01"], ids)
	}
	if seen["laptop-02"] != 1 {
		t.Fatalf("laptop-02 was lost during laptop-01's rotation: %v", ids)
	}
	for _, l := range readRoster(t, roster) {
		if l == first {
			t.Fatal("laptop-01's OLD key is still in the roster — the rotation did not take effect")
		}
	}
}

// The gateway aborts startup on a roster line it cannot parse. A command that quietly rewrote the file
// around such a line would produce one that loads, having dropped agents nobody chose to unenrol.
func TestAMalformedRosterIsRefusedAndLeftUntouched(t *testing.T) {
	roster := filepath.Join(t.TempDir(), "roster")
	original := "# our fleet\ngood-agent AAAA\nthis line has three fields here\n"
	if err := os.WriteFile(roster, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	if code := run([]string{"posture-enroll", "--agent", "new-agent", "--roster", roster, "--out", t.TempDir()}); code == 0 {
		t.Fatal("a malformed roster was accepted")
	}
	after, err := os.ReadFile(roster)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != original {
		t.Fatalf("the roster was rewritten despite the refusal:\n got %q\nwant %q", after, original)
	}
}

func TestRosterCommentsSurviveEnrolment(t *testing.T) {
	roster := filepath.Join(t.TempDir(), "roster")
	if err := os.WriteFile(roster, []byte("# managed by ops, do not edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	enroll(t, roster, "laptop-01")

	blob, err := os.ReadFile(roster)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "# managed by ops, do not edit") {
		t.Fatalf("the operator's comment was dropped: %q", blob)
	}
	if ids := agentsIn(t, roster); len(ids) != 1 || ids[0] != "laptop-01" {
		t.Fatalf("agents = %v, want [laptop-01]", ids)
	}
}

func TestRosterLinesOnAnAbsentFileStartsEmpty(t *testing.T) {
	lines, err := rosterLines(filepath.Join(t.TempDir(), "nope"), "a")
	if err != nil {
		t.Fatalf("an absent roster is the first enrolment, not an error: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("got %v, want no lines", lines)
	}
}
