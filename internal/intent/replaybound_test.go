package intent_test

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/intent"
)

// SEC-B: the fleet-control replay bound was a plain uint64 struct field, so it reset to zero on every
// restart.
//
// That is the whole defence against the sharpest replay in the system — a captured fleet-wide DISABLE,
// re-sent after an operator restored enforcement. The publisher's sequence has been persisted since D66
// with the reason spelled out ("without it a restart replays sequence numbers"), but the CONSUMER is
// where a replay is refused, and docs/threat-model.md claimed the sequence was "stored rather than held
// in memory" of the consumer too. It was not, and an attacker who could wait for a reboot — or cause one
// — got every captured control back, bounded only by its own TTL.

// failingStore is a bound that loads clean and cannot be written: the unwritable-directory case, which is
// how this fails in production (a container whose /var/lib is read-only, a unit file with
// ProtectSystem=strict).
type failingStore struct {
	loaded    uint64
	loadErr   error
	writes    int
	failAfter int // writes strictly greater than this fail; 0 = the startup probe already fails
}

func (s *failingStore) Load() (uint64, error) { return s.loaded, s.loadErr }
func (s *failingStore) Reserve(hw uint64) error {
	s.writes++
	if s.writes > s.failAfter {
		return errors.New("read-only file system")
	}
	s.loaded = hw
	return nil
}

func disable(t *testing.T, priv ed25519.PrivateKey, seq uint64) []byte {
	t.Helper()
	return control(t, priv, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE, seq, time.Now().Add(time.Hour), 1)
}

// TestARestartDoesNotReopenTheReplayWindow is the defect, stated as the sequence of events an attacker
// actually runs: capture a legitimate DISABLE off the wire, wait for the operator to restore enforcement,
// wait for a restart, re-send.
//
// Before SEC-B the re-send was accepted, because the new process's `applied` was 0 and the captured
// control verified perfectly — a valid signature, an unexpired TTL, a sequence above zero.
//
// Mutation: drop the Load in NewPersistentFleetControlSubscriber (start every process at 0, which is what
// the code did) → the replayed DISABLE is applied and enforcement stops → this FAILS.
func TestARestartDoesNotReopenTheReplayWindow(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state", "fleet-control.seq")
	captured := disable(t, priv, 5)

	// The host's first life: a real disable, then the operator restores enforcement.
	sw := &fakeSwitch{}
	bound, err := intent.OpenReplayBound(path, "")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := intent.NewPersistentFleetControlSubscriber(pub, sw, bound)
	if err != nil {
		t.Fatalf("opening the replay bound: %v", err)
	}
	if err := sub.Apply(captured); err != nil {
		t.Fatalf("the legitimate disable was rejected: %v", err)
	}
	restore := control(t, priv, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_RESTORE, 6, time.Now().Add(time.Hour), 1)
	if err := sub.Apply(restore); err != nil {
		t.Fatalf("the restore was rejected: %v", err)
	}
	if engaged, _ := sw.state(); engaged {
		t.Fatal("enforcement is still disabled after a restore — the fixture is wrong")
	}

	// THE RESTART. A brand-new subscriber over the same file, exactly as the binary builds one at boot.
	sw2 := &fakeSwitch{}
	bound2, err := intent.OpenReplayBound(path, "")
	if err != nil {
		t.Fatal(err)
	}
	sub2, err := intent.NewPersistentFleetControlSubscriber(pub, sw2, bound2)
	if err != nil {
		t.Fatalf("reopening the replay bound: %v", err)
	}
	if got := sub2.AppliedSequence(); got != 6 {
		t.Fatalf("the restarted consumer's replay bound is %d, want 6 — it did not resume from disk", got)
	}

	if err := sub2.Apply(captured); err == nil {
		t.Error("a DISABLE captured before the restart was ACCEPTED after it — the replay bound reset " +
			"to zero, which is the whole of this channel's replay defence")
	}
	if engaged, reason := sw2.state(); engaged {
		t.Errorf("enforcement was stopped fleet-wide by a replayed control (%q)", reason)
	}
	if sub2.Rejected.Load() != 1 {
		t.Errorf("the replay was not counted as a rejection (%d) — a replay flood must be observable",
			sub2.Rejected.Load())
	}
}

// TestTheBoundIsPersistedBeforeTheControlIsApplied pins the ORDER, which is the part that is easy to get
// backwards and impossible to notice.
//
// Applying first and persisting after would pass every other test here: the switch flips, the counters
// move, the file eventually holds the right number. It fails only when the process dies between the two —
// and then it restores a bound BELOW a control that already ran, which is precisely the replay the bound
// exists to refuse.
//
// The test states it as a refusal instead: if the bound cannot be written, the control does not take
// effect. That is observable without simulating a crash, and it is the same invariant.
//
// Mutation: move the Reserve after f.target.Engage, or ignore its error → the switch engages on an
// unpersisted control → this FAILS.
func TestTheBoundIsPersistedBeforeTheControlIsApplied(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sw := &fakeSwitch{}
	// failAfter: 1 lets the startup probe through and fails the first real control.
	store := &failingStore{failAfter: 1}
	sub, err := intent.NewPersistentFleetControlSubscriber(pub, sw, store)
	if err != nil {
		t.Fatalf("construction: %v", err)
	}

	err = sub.Apply(disable(t, priv, 9))
	if err == nil {
		t.Fatal("a control whose replay bound could not be persisted was ACCEPTED")
	}
	if !strings.Contains(err.Error(), "could not be persisted") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if engaged, _ := sw.state(); engaged {
		t.Error("enforcement was DISABLED by a control whose replay bound was never written — a restart " +
			"would then accept the same control again, and this channel fails toward ENFORCING")
	}
	if got := sub.AppliedSequence(); got != 0 {
		t.Errorf("the in-memory bound advanced to %d despite the write failing — memory and disk now "+
			"disagree, and disk is what survives", got)
	}
	if sub.Rejected.Load() != 1 {
		t.Errorf("rejections = %d, want 1", sub.Rejected.Load())
	}
}

// TestACorruptReplayBoundRefusesToStart. A truncated or garbage file is the one case where "start fresh"
// is the tempting behaviour and the wrong one: a bound of 0 is exactly the state an attacker holding
// captured controls wants, so a file we cannot read is a reason to refuse to run, not to run unbounded.
//
// Mutation: treat a Load error as 0 → construction succeeds → this FAILS.
func TestACorruptReplayBoundRefusesToStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet-control.seq")
	if err := os.WriteFile(path, []byte("42"), 0o600); err != nil { // 2 bytes; the format is 8
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = intent.OpenReplayBound(path, "")
	if err == nil {
		t.Fatal("a corrupt replay bound was accepted — the consumer would come up with a bound of 0 and " +
			"replay every captured control")
	}
	// AND IT IS NOT DOWNGRADABLE. The binaries fall back to an in-memory bound when the DEFAULT path
	// merely cannot be written, which is a legitimate deployment. Corruption must not take that exit: it
	// means a bound existed and is now unreadable, and continuing from zero is the attacker's outcome.
	if errors.Is(err, intent.ErrBoundUnwritable) {
		t.Errorf("a corrupt bound reports as merely unwritable (%v), so a caller would degrade to an "+
			"in-memory bound instead of stopping", err)
	}

	// The subscriber refuses it too, for a caller that opened the store some other way.
	if _, err := intent.NewPersistentFleetControlSubscriber(pub, &fakeSwitch{},
		&failingStore{loadErr: errors.New("corrupt")}); err == nil {
		t.Error("the subscriber accepted a bound it could not read")
	}
}

// TestAnUnwritableBoundIsReportedAsSuch is the other half of the previous test: the ONE failure a caller
// is allowed to downgrade must be distinguishable, or the distinction is decorative.
//
// Mutation: return a bare error instead of wrapping ErrBoundUnwritable → the binaries stop falling back
// and a read-only root filesystem becomes a boot failure → this FAILS.
func TestAnUnwritableBoundIsReportedAsSuch(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil { // readable, not writable
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, err := intent.OpenReplayBound(filepath.Join(dir, "fleet-control.seq"), "")
	if err == nil {
		t.Skip("the bound was writable in a 0500 directory — running as root, so this case is untestable here")
	}
	if !errors.Is(err, intent.ErrBoundUnwritable) {
		t.Errorf("an unwritable bound reported %v, which does not identify itself as unwritable — the "+
			"caller cannot then tell it apart from corruption, and either refuses to boot on a read-only "+
			"filesystem or degrades on a corrupt bound", err)
	}
}

// TestTheReplayBoundIsProvenWritableAtStartup.
//
// Without the probe an unwritable directory is discovered when the first real control arrives, and by
// then the control is refused — a fleet-wide disable failing at the exact moment an incident needs it,
// for a reason that was knowable at boot. This is the cheap version of that discovery.
//
// Mutation: remove the Reserve(applied) probe from the constructor → construction succeeds on an
// unwritable bound → this FAILS.
func TestTheReplayBoundIsProvenWritableAtStartup(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	store := &failingStore{loaded: 3} // failAfter 0: the probe itself fails
	if _, err := intent.NewPersistentFleetControlSubscriber(pub, &fakeSwitch{}, store); err == nil {
		t.Error("a replay bound that cannot be written was accepted at startup — the failure surfaces " +
			"instead when a control arrives, which is during an incident")
	}
}

// TestTheReplayBoundRefusesToShareTheTelemetrySequenceFile.
//
// Both hold a uint64 in the same format, and one is an obvious place to put the other. Sharing them is
// silent and close to undiagnosable: the telemetry high-water advances every hundred published messages,
// so within seconds of boot the replay bound is in the thousands and EVERY legitimate fleet control is
// refused as a replay. The host looks healthy and can no longer be told to stop enforcing.
//
// Mutation: drop the comparison → the two paths are accepted → this FAILS.
func TestTheReplayBoundRefusesToShareTheTelemetrySequenceFile(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "seq")

	if _, err := intent.OpenReplayBound(shared, shared); err == nil {
		t.Error("the replay bound and the telemetry sequence were allowed to share a file")
	}
	// The same file reached by a different spelling is the same file. A textual comparison would miss it,
	// and an operator writing one path relative and one absolute is not doing anything unusual.
	if _, err := intent.OpenReplayBound(shared, filepath.Join(dir, ".", "seq")); err == nil {
		t.Error("a differently-spelled path to the same file was accepted — the guard compares strings, " +
			"not files")
	}
	// Different files are fine, which is the case that must keep working.
	if _, err := intent.OpenReplayBound(shared, filepath.Join(dir, "telemetry.seq")); err != nil {
		t.Errorf("two distinct paths were refused: %v", err)
	}
}

// TestAnInMemoryBoundIsStillReachable — NewFleetControlSubscriber keeps working, because a read-only or
// ephemeral root filesystem is a real deployment and refusing to start there would be worse than the
// window. What must not happen is that it becomes the SILENT default; the binaries warn, and this only
// pins that the constructor still means "no persistence" rather than "no bound".
func TestAnInMemoryBoundIsStillReachable(t *testing.T) {
	sub, sw, priv := newSub(t)
	if err := sub.Apply(disable(t, priv, 4)); err != nil {
		t.Fatalf("in-memory subscriber rejected a valid disable: %v", err)
	}
	if engaged, _ := sw.state(); !engaged {
		t.Fatal("the disable did not take effect")
	}
	// The bound still holds WITHIN a process; it is only the restart that loses it.
	if err := sub.Apply(disable(t, priv, 4)); err == nil {
		t.Error("an in-memory subscriber accepted a replay inside one process")
	}
}
