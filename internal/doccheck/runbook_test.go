package doccheck_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// PLAT-9: the runbook's component table must match the binaries that exist — checked in BOTH directions.
//
// A runbook is read under pressure. One that omits a component, or names one that was removed, costs an
// operator time exactly when they have none. Documentation drifts silently, so the part that must be
// correct — WHAT EXISTS — is bound to reality by a test rather than by intention.
//
// Mutation: check only one direction → a documented-but-removed binary passes → FAILS.
func TestRunbookDocumentsExactlyTheShippedBinaries(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbook.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(body)

	entries, err := os.ReadDir(filepath.Join("..", "..", "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	shipped := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			shipped[e.Name()] = true
		}
	}
	if len(shipped) == 0 {
		t.Fatal("found no commands — the guard is not looking at cmd/, so it proves nothing")
	}

	// Direction 1: everything that ships is documented.
	for name := range shipped {
		if !strings.Contains(doc, "`"+name+"`") {
			t.Errorf("%s ships but the runbook does not name it — an operator meets a component the "+
				"documentation does not mention", name)
		}
	}

	// Direction 2: everything documented still exists. This is the half a one-directional check misses,
	// and the more damaging one: a runbook that sends someone to a binary that was removed.
	for _, line := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(line, "| `openshield") {
			continue
		}
		name := strings.TrimSpace(strings.SplitN(line, "|", 3)[1])
		name = strings.Trim(name, "` ")
		if !shipped[name] {
			t.Errorf("the runbook documents %q, which does not exist in cmd/ — under pressure that "+
				"sends an operator looking for something that is not there", name)
		}
	}
}
