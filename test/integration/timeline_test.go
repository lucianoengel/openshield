//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// THE INVESTIGATION SURFACE (T-010): `openshieldctl timeline`.
//
// Phase 1 cut the React investigation UI and put this in its place — T-010's acceptance was "a seeded
// incident renders as an ordered timeline". It is, in other words, the ONLY way an operator reconstructs
// what happened, and the whole reason the ledger's ordering guarantees matter to anyone.
//
// The integration suite had never invoked it. That gap was invisible to a settings audit, because the
// subcommand takes flags rather than environment variables — which is a good argument against measuring
// coverage by settings at all: a binary's executable paths are not enumerable from its configuration.
//
// What these pin, beyond "it runs": the timeline is ORDERED, it is FILTERABLE (an investigator narrows to
// one subject), it REPORTS ITS OWN VERIFICATION STATE rather than presenting entries as trustworthy, and
// it carries no file content.

// seedTimeline runs the engine over a watch directory so real decisions land in the ledger, and returns
// the subject the events were attributed to.
func seedTimeline(t *testing.T, stack *Stack, work string, files map[string]string) {
	t.Helper()
	watch := t.TempDir()
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
	})
	eng.WaitForOutput("engine observing", 90*time.Second)

	pool := openPool(t, stack.DSN)
	count := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for name, body := range files {
		// THE BASELINE IS TAKEN BEFORE THE WRITE, and it used to be taken after it. That ordering is a
		// race the ENGINE WINS on any machine fast enough: the row lands ~90ms after the file appears,
		// `count()` then already includes it, and the loop waits out its full 60s for a second row that
		// is never coming. It fails deterministically here and would have been intermittent on slower
		// hardware — the worst version of the bug, because a test that fails only sometimes gets retried
		// rather than read.
		//
		// One file at a time, so the ledger's ORDER reflects the order things happened — which is the
		// property the timeline exists to present and cannot be asserted on a racing batch.
		before := count()
		if err := os.WriteFile(filepath.Join(watch, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		Eventually(t, 60*time.Second, "the decision for "+name+" to be recorded", func() bool {
			return count() > before
		})
	}
	eng.Stop() // flush and release the signer before the CLI reads the chain
}

// TestTheTimelineRendersAnOrderedInvestigation.
func TestTheTimelineRendersAnOrderedInvestigation(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	seedTimeline(t, stack, work, map[string]string{
		"first.txt":  "nothing interesting here\n",
		"second.csv": cpfBody,
	})

	out, err := runCapture(t, "openshieldctl", nil, "timeline", "--dsn", stack.DSN)
	if err != nil {
		t.Fatalf("openshieldctl timeline: %v\n%s", err, out)
	}

	// 1. IT REPORTS ITS OWN VERIFICATION STATE FIRST. An investigation surface that renders entries
	// without saying whether the chain verifies invites an investigator to treat unverified history as
	// evidence — which is the whole distinction between tamper-EVIDENT and tamper-proof (D12).
	if !contains(out, "VERIFICATION:") {
		t.Errorf("the timeline rendered no verification header. Entries presented without their "+
			"verification state read as trustworthy, which is the claim this project does not make:\n%s", out)
	}

	// 2. IT IS ORDERED. The sequence numbers must ascend down the page — a timeline whose order is the
	// database's default row order is not a timeline, it is a table.
	var seqs []int
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, "seq=")
		if i < 0 {
			continue
		}
		field := line[i+4:]
		if j := strings.IndexByte(field, ' '); j >= 0 {
			field = field[:j]
		}
		n, err := strconv.Atoi(field)
		if err != nil {
			continue
		}
		seqs = append(seqs, n)
	}
	if len(seqs) < 2 {
		t.Fatalf("the timeline showed %d entries; the scenario seeded at least two decisions:\n%s",
			len(seqs), out)
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] < seqs[i-1] {
			t.Errorf("the timeline is not ordered: seq %d follows %d\n%s", seqs[i], seqs[i-1], out)
			break
		}
	}

	// 3. IT CARRIES NO CONTENT. The ledger holds type+confidence+count (D10); a timeline that printed the
	// matched text would make the investigation surface the leak.
	if contains(out, "111.444.777-35") || contains(out, "11144477735") {
		t.Errorf("the timeline printed the CPF from the seeded file — the investigation surface must not "+
			"be where the sensitive value finally appears:\n%s", out)
	}
}

// TestTheTimelineFiltersToOneSubject is what makes it an investigation tool rather than a dump.
//
// An investigator asks about ONE subject. A filter that silently matched everything would look identical
// on a small ledger and be useless on a real one — so the assertion is that a filter naming a subject
// that does not exist returns NOTHING, which no accidental match can satisfy.
func TestTheTimelineFiltersToOneSubject(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	seedTimeline(t, stack, work, map[string]string{"only.csv": cpfBody})

	out, err := runCapture(t, "openshieldctl", nil,
		"timeline", "--dsn", stack.DSN, "--subject", "subject-that-never-existed")
	if err != nil {
		t.Fatalf("openshieldctl timeline --subject: %v\n%s", err, out)
	}
	if !contains(out, "no entries match the filter") {
		t.Errorf("filtering to a subject with no activity still rendered entries. A filter that does not "+
			"narrow is worse than none: it makes an investigator believe they have looked at one "+
			"subject's history when they are looking at everyone's:\n%s", out)
	}
	// And the header is still there — an empty result must still say whether the chain verifies, or an
	// investigator cannot tell "nothing happened" from "nothing could be read".
	if !contains(out, "VERIFICATION:") {
		t.Errorf("an empty filtered timeline omitted the verification header:\n%s", out)
	}
}
