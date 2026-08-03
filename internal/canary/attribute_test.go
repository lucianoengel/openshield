package canary_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/canary"
)

// HIPS-8 — PER-PROCESS ATTRIBUTION.
//
// The detector answers "something is encrypting this tree", which is true and unactionable. The next
// question is always WHICH PROCESS, and until it is answered the only response available is taking the
// machine off the network — a containment that routinely costs more than the incident.

func requireProc(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("attribution reads /proc")
	}
}

// holder starts a child process that opens every file in dir and then waits, so the test has a REAL
// process holding REAL descriptors — which is the only thing this code reads.
//
// A child rather than opening the files in-process: the scan excludes its own pid deliberately (this
// engine reads canaries itself to measure entropy), so an in-process fixture would be excluded and the
// test would pass by finding nothing.
func holder(t *testing.T, dir string) *exec.Cmd {
	t.Helper()
	// `tail -f` on the files keeps them open and the process alive, using nothing but coreutils.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-f"}
	for _, e := range entries {
		args = append(args, filepath.Join(dir, e.Name()))
	}
	if len(args) == 1 {
		t.Fatal("the directory is empty, so no fixture could hold anything open")
	}
	cmd := exec.Command("tail", args...)
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start the fixture process: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	// tail opens its files before it blocks; wait until the descriptors are actually there rather than
	// sleeping a guessed interval.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a := canary.Attribute(dir, 0); len(a.Suspects) > 0 {
			return cmd
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the fixture process never showed up as holding the canaries open")
	return nil
}

// THE HEADLINE: the process holding the canaries open is named, with what a kill needs.
//
// Mutation (drop the underTree check, or the descriptor walk): no suspect is found → FAIL.
func TestTheProcessHoldingTheCanariesOpenIsNamed(t *testing.T) {
	requireProc(t)
	dir := t.TempDir()
	if _, err := canary.Plant(dir, 4); err != nil {
		t.Fatal(err)
	}
	cmd := holder(t, dir)

	att := canary.Attribute(dir, 0)
	if !att.Supported {
		t.Fatal("attribution reported itself unsupported on linux")
	}
	var found *canary.Suspect
	for i := range att.Suspects {
		if att.Suspects[i].PID == cmd.Process.Pid {
			found = &att.Suspects[i]
		}
	}
	if found == nil {
		t.Fatalf("the process holding %d canaries open was not named (suspects=%v) — a ransomware "+
			"detection nobody can act on leaves taking the whole machine off the network as the only "+
			"response", 4, att.Suspects)
	}
	if found.OpenPaths < 4 {
		t.Errorf("the suspect holds %d paths under the tree, want >=4 — the count is the ranking "+
			"signal that separates a process encrypting a directory from an editor with one file open",
			found.OpenPaths)
	}
	if found.StartTicks == 0 {
		t.Errorf("the suspect carries no start time — with the pid it identifies the process INSTANCE, " +
			"and without it a kill decided now can land on a recycled pid (HIPS-7)")
	}
	if found.Exe == "" {
		t.Errorf("the suspect has no executable path, though this test owns the process and can read it")
	}
}

// THE DETECTOR IS NEVER ITS OWN SUSPECT.
//
// This engine reads the canaries to measure their entropy, so it is — briefly and by design — a process
// holding canary files open. Attributing a ransomware detection to the detector is the most embarrassing
// false positive available and the one this code is structurally most likely to produce.
//
// Mutation (drop the `pid == self` skip): this process appears while holding a canary open → FAIL.
func TestTheDetectorIsNeverItsOwnSuspect(t *testing.T) {
	requireProc(t)
	dir := t.TempDir()
	paths, err := canary.Plant(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Hold one open IN THIS PROCESS, exactly as the entropy read does.
	f, err := os.Open(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	att := canary.Attribute(dir, 0)
	for _, s := range att.Suspects {
		if s.PID == os.Getpid() {
			t.Fatalf("the detector attributed the detection to ITSELF (pid %d, %d paths) — it reads the "+
				"canaries to measure entropy, so it is always a candidate, and naming it would send an "+
				"operator to kill their own agent", s.PID, s.OpenPaths)
		}
	}
}

// A PROCESS THAT TOUCHES NOTHING IN THE TREE IS NOT A SUSPECT, so the test above is not passing because
// everything is excluded.
func TestAnUnrelatedProcessIsNotASuspect(t *testing.T) {
	requireProc(t)
	dir := t.TempDir()
	if _, err := canary.Plant(dir, 3); err != nil {
		t.Fatal(err)
	}
	// A second directory, held open by a real process, which must NOT appear against the first.
	other := t.TempDir()
	if _, err := canary.Plant(other, 3); err != nil {
		t.Fatal(err)
	}
	cmd := holder(t, other)

	att := canary.Attribute(dir, 0)
	for _, s := range att.Suspects {
		if s.PID == cmd.Process.Pid {
			t.Fatalf("a process holding files in a DIFFERENT directory was named against %s — an "+
				"attribution that names everyone names nobody", dir)
		}
	}
}

// "WE COULD NOT LOOK" IS NOT "NOTHING WAS FOUND".
//
// Reading another process's descriptor table needs to be the same user or hold CAP_SYS_PTRACE. An
// unprivileged agent therefore sees only its OWN processes and would find nothing every time, while
// reporting a clean result — the reassuring answer produced by an inability to look.
//
// Mutation (drop the Unreadable count, or have Blind() ignore it): a scan that saw nothing because it was
// refused everywhere reads as clean → FAIL.
func TestBeingUnableToLookIsDistinguishableFromFindingNothing(t *testing.T) {
	requireProc(t)
	dir := t.TempDir()
	if _, err := canary.Plant(dir, 3); err != nil {
		t.Fatal(err)
	}

	// A clean scan of a tree nobody has open: not blind, just empty.
	att := canary.Attribute(dir, 0)
	if len(att.Suspects) != 0 {
		t.Skipf("something on this machine holds %s open; the assertion below needs a quiet tree", dir)
	}
	if att.Scanned == 0 {
		t.Fatal("the scan examined no processes at all")
	}
	if att.Unreadable == 0 && att.Blind() {
		t.Fatal("an empty scan with nothing in the way reported itself BLIND — a caller would escalate " +
			"on every quiet machine")
	}

	// The synthetic version of the case that matters: nothing found, something in the way.
	blind := canary.Attribution{Supported: true, Scanned: 400, Unreadable: 399}
	if !blind.Blind() {
		t.Fatal("a scan that found nothing while being refused 399 processes reported itself clean — " +
			"an unprivileged agent produces exactly that result on every run, and an operator reading " +
			"it is being told the machine is fine by a component that never got to look")
	}
	// And a scan that FOUND something is not blind, however much it was refused: the finding stands on
	// its own, and calling it unreliable would suppress a real attribution.
	sighted := canary.Attribution{Supported: true, Scanned: 400, Unreadable: 399,
		Suspects: []canary.Suspect{{PID: 42, OpenPaths: 9}}}
	if sighted.Blind() {
		t.Fatal("a scan that NAMED a suspect reported itself blind")
	}
}

// AN UNSUPPORTED PLATFORM SAYS SO rather than returning an empty result that reads as clean.
func TestAnUnsupportedPlatformIsNotACleanResult(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux has /proc; the stub's contract is asserted by the type's zero value below")
	}
	att := canary.Attribute(t.TempDir(), 0)
	if att.Supported {
		t.Fatal("a platform with no /proc reported attribution as supported")
	}
	if !att.Blind() {
		t.Fatal("an unsupported platform did not report itself blind — a caller would read its empty " +
			"suspect list as evidence that nothing was responsible")
	}
}

// THE RANKING IS STABLE AND BOUNDED. It ends up in an event id and in an operator's notes, so a set that
// reorders between two scans of the same state reads as the situation having changed.
func TestSuspectsAreRankedByOpenCountAndBounded(t *testing.T) {
	requireProc(t)
	dir := t.TempDir()
	if _, err := canary.Plant(dir, 6); err != nil {
		t.Fatal(err)
	}
	holder(t, dir)

	first := canary.Attribute(dir, 0)
	second := canary.Attribute(dir, 0)
	if len(first.Suspects) != len(second.Suspects) {
		t.Skip("the process set changed between scans on this machine")
	}
	for i := range first.Suspects {
		if first.Suspects[i].PID != second.Suspects[i].PID {
			t.Fatalf("two scans of the same state ordered the suspects differently at %d (%d vs %d)",
				i, first.Suspects[i].PID, second.Suspects[i].PID)
		}
	}
	if len(first.Suspects) > 0 {
		bounded := canary.Attribute(dir, 1)
		if len(bounded.Suspects) != 1 {
			t.Errorf("max=1 returned %d suspects", len(bounded.Suspects))
		}
		// SCANNED DESCRIBES THE WALK, NOT THE RESULT — bounding the suspect list must not shrink it.
		//
		// This was asserted as exact equality against an earlier scan, and it failed in CI at 166 vs
		// 165. Exact equality was never a property of the system: Scanned counts /proc entries on a
		// LIVE machine, so two scans legitimately differ by whatever started or exited between them. It
		// was a property of an idle developer laptop, and a test that depends on the machine being idle
		// is a test that goes red for reasons unrelated to the code — which is how a suite stops being
		// read.
		//
		// The claim is still worth pinning, and separating "the whole process table" from "at most
		// max" does not need exactness: the mutation it defends against (counting suspects AFTER the
		// bound is applied) drives Scanned to len(Suspects), which is 1 here. A tolerance well above
		// process churn and far below that gap keeps the assertion decisive.
		churn := first.Scanned/10 + 5
		if diff := first.Scanned - bounded.Scanned; diff > churn {
			t.Errorf("bounding the RESULT dropped the SCANNED count from %d to %d (more than the %d "+
				"this machine's churn explains) — the counts must describe the whole system, not the "+
				"prefix that fitted", first.Scanned, bounded.Scanned, churn)
		}
		if bounded.Scanned <= len(bounded.Suspects) {
			t.Errorf("scanned=%d with %d suspect(s) returned — Scanned is reporting the result rather "+
				"than the walk", bounded.Scanned, len(bounded.Suspects))
		}
	}
}

// THE START TIME SURVIVES A PROCESS THAT NAMED ITSELF AWKWARDLY.
//
// /proc/<pid>/stat's second field is the executable's comm IN PARENTHESES, and a process is free to have
// spaces or a ')' in its name. Splitting the line on whitespace shifts every later field for exactly the
// processes that chose a name to make that happen — and this value is what a kill uses to avoid a
// recycled pid, so getting it wrong points an ENFORCEMENT at the wrong process. An attacker picking such
// a name is a two-line change for them.
//
// The test computes BOTH parses itself and requires them to disagree for this fixture, so it cannot pass
// by accident on a machine where the naive one happens to be right — which is why the earlier tests, run
// against a process called `tail`, could not catch this.
func TestTheStartTimeIsParsedAfterTheCommRatherThanBySplitting(t *testing.T) {
	requireProc(t)
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	src, err := os.ReadFile(sleep)
	if err != nil {
		t.Skipf("cannot read %s: %v", sleep, err)
	}
	// A name containing BOTH a ')' and a space — the two things that break a naive split.
	dir := t.TempDir()
	awkward := filepath.Join(dir, "s) e ep")
	if err := os.WriteFile(awkward, src, 0o755); err != nil { //nolint:gosec // an executable fixture must be executable
		t.Fatal(err)
	}
	cmd := exec.Command(awkward, "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start the awkwardly-named fixture: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	pid := cmd.Process.Pid

	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		t.Skipf("cannot read the fixture's stat: %v", err)
	}
	line := string(raw)

	// The CORRECT rule: everything after the final ')', field 22 overall = index 19 here.
	after := strings.Fields(line[strings.LastIndex(line, ")")+1:])
	if len(after) <= 19 {
		t.Skipf("unexpected stat layout: %q", line)
	}
	correct, err := strconv.ParseUint(after[19], 10, 64)
	if err != nil {
		t.Skipf("unparseable start time %q", after[19])
	}
	// The NAIVE rule: split the whole line, take field 22 (index 21).
	whole := strings.Fields(line)
	var naive uint64
	if len(whole) > 21 {
		naive, _ = strconv.ParseUint(whole[21], 10, 64)
	}
	if naive == correct {
		t.Skipf("this fixture's name did not shift the fields (comm %q), so the test cannot "+
			"distinguish the two parses", line[:strings.LastIndex(line, ")")+1])
	}

	att := canary.Attribute(dir, 0)
	_ = att // the fixture holds no descriptors under dir; this call only proves Attribute is unharmed

	got := canary.StartTicksForTest(strconv.Itoa(pid))
	if got != correct {
		t.Fatalf("start time = %d, want %d (the naive split gives %d). A process is free to put a ')' "+
			"or a space in its name, and every later field shifts for exactly those processes — this "+
			"value is what a kill revalidates against, so a wrong one aims an enforcement at whatever "+
			"pid was recycled", got, correct, naive)
	}
}
