package doccheck_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/doccheck"
)

// THE SPEC STORE'S OWN INTEGRITY (D322).
//
// 170 of 526 requirements this project wrote, reviewed and shipped had disappeared from the capability
// files that are supposed to hold them. `openspec/specs/control-plane/spec.md` was one requirement long
// — the body of a single delta — with thirty-six other changes' work gone. Two failures produced it, and
// both report success: archiving a change without syncing its delta, and a sync that OVERWROTE the
// capability file with the delta being merged into it.
//
// The consequence is not that the specs were wrong. They were INCOMPLETE, and an absent requirement is
// indistinguishable from a capability nobody ever asked for — so the next person to open the ledger's
// spec finds no mention of hash chaining and reasonably concludes the design is theirs to make. It also
// compounds, because every new delta is written and validated against whatever the file currently says.

func TestAnArchivedRequirementMustSurviveInItsCapabilitySpec(t *testing.T) {
	deltas, specs := readSpecStore(t)
	gaps, err := doccheck.CheckSpecStore(deltas, specs)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) == 0 {
		return
	}
	var b strings.Builder
	for _, g := range gaps {
		b.WriteString("\n  " + g.String())
	}
	t.Errorf("%d requirement(s) introduced by an archived change are missing from their capability "+
		"spec. Restore them with scripts/spec-store-restore.py — they are recoverable, because the "+
		"archived delta still holds them. A capability file that has lost a requirement does not read "+
		"as incomplete, it reads as a capability nobody asked for:%s", len(gaps), b.String())
}

// TestTheSpecStoreGuardCatchesALoss is the mutation, held permanently rather than run by hand.
//
// Without it, the check above is satisfied by a store that is already whole and would keep passing if
// the comparison were inverted, emptied, or quietly reduced to "the capability file exists".
func TestTheSpecStoreGuardCatchesALoss(t *testing.T) {
	deltas := map[string]map[string]string{
		"2026-01-01-first": {"ledger": "## ADDED Requirements\n\n### Requirement: Entries chain\n\ntext\n"},
		"2026-02-01-later": {"ledger": "## ADDED Requirements\n\n### Requirement: Keys evolve\n\ntext\n"},
	}
	// The capability kept only the later change's requirement — the exact damage seen in the tree.
	specs := map[string]string{"ledger": "## Requirements\n\n### Requirement: Keys evolve\n\ntext\n"}

	gaps, err := doccheck.CheckSpecStore(deltas, specs)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 1 {
		t.Fatalf("want exactly 1 gap, got %d: %v", len(gaps), gaps)
	}
	if gaps[0].Requirement != "Entries chain" || gaps[0].Change != "2026-01-01-first" {
		t.Errorf("the gap must name the requirement AND the change that introduced it, so it can be "+
			"recovered; got %+v", gaps[0])
	}
}

// TestARequirementWithNoArchivedSourceIsAllowed is the other direction, and it is what keeps the guard
// usable. A capability may carry requirements authored directly rather than through a change — 28 do —
// and a check that flagged those would force every direct edit through a ceremony, which is how a guard
// comes to be deleted rather than obeyed.
func TestARequirementWithNoArchivedSourceIsAllowed(t *testing.T) {
	deltas := map[string]map[string]string{
		"2026-01-01-first": {"ledger": "## ADDED Requirements\n\n### Requirement: Entries chain\n\ntext\n"},
	}
	specs := map[string]string{
		"ledger": "## Requirements\n\n### Requirement: Entries chain\n\ntext\n\n" +
			"### Requirement: Written by hand\n\ntext\n",
	}
	gaps, err := doccheck.CheckSpecStore(deltas, specs)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 0 {
		t.Errorf("a requirement with no archived source was flagged: %v", gaps)
	}
}

// TestAnUnknownDeltaSectionIsRefused. Ignoring a section is the behaviour that produced this whole
// repair, so meeting one the check has not been taught must be an ERROR, never a skip.
func TestAnUnknownDeltaSectionIsRefused(t *testing.T) {
	deltas := map[string]map[string]string{
		"2026-01-01-first": {"ledger": "## REMOVED Requirements\n\n### Requirement: Gone\n\ntext\n"},
	}
	if _, err := doccheck.CheckSpecStore(deltas, map[string]string{"ledger": ""}); err == nil {
		t.Error("an unrecognized delta section was accepted. A section this check cannot interpret must " +
			"stop it, because silently ignoring one is exactly how the requirements were lost")
	}
}

// readSpecStore loads the real archive and the real capability files.
func readSpecStore(t *testing.T) (deltas map[string]map[string]string, specs map[string]string) {
	t.Helper()
	deltas, specs = map[string]map[string]string{}, map[string]string{}

	changes, err := filepath.Glob("../../openspec/changes/archive/*/specs/*/spec.md")
	if err != nil || len(changes) == 0 {
		t.Fatalf("no archived deltas found (err=%v) — this check is meaningless if it reads nothing", err)
	}
	for _, p := range changes {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rel := strings.SplitN(p, "/archive/", 2)[1]
		change := strings.SplitN(rel, "/", 2)[0]
		capability := strings.SplitN(strings.SplitN(p, "/specs/", 2)[1], "/", 2)[0]
		if deltas[change] == nil {
			deltas[change] = map[string]string{}
		}
		deltas[change][capability] = string(b)
	}

	merged, _ := filepath.Glob("../../openspec/specs/*/spec.md")
	for _, p := range merged {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		specs[filepath.Base(filepath.Dir(p))] = string(b)
	}
	return deltas, specs
}
