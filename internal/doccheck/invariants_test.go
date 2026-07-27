package doccheck_test

import (
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// INVARIANTS.md NAMES TESTS. THIS CHECKS THEY EXIST.
//
// The document's whole claim is that each invariant is backed by a test that fails when the property
// regresses. A renamed or deleted test would turn a demonstrated claim back into prose — silently, and in
// the one document whose entire purpose is not being prose.
//
// It checks EXISTENCE, and says so rather than implying more: it cannot check that a named test still
// asserts what it did when it was named. That is what the mutation runs recorded in the document are
// for, and they are a human discipline, not an automated one.
var invariantTest = regexp.MustCompile("`(Test[A-Za-z0-9_]+)`")

// claimSurfaces are the documents that back a security claim with a named test. Both make the same kind
// of promise, so both get the same guard: THREAT_MODEL's "proven by" rows are worth exactly as much as
// INVARIANTS' are, and a stale name in either turns a demonstration into a sentence.
var claimSurfaces = []string{"../../INVARIANTS.md", "../../docs/threat-model.md"}

func TestEveryTestNamedInInvariantsExists(t *testing.T) {
	named := map[string]bool{}
	for _, path := range claimSurfaces {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, m := range invariantTest.FindAllStringSubmatch(string(body), -1) {
			named[m[1]] = true
		}
	}
	if len(named) < 5 {
		t.Fatalf("the claim surfaces name only %d tests — too few for the document to be doing its job, and "+
			"a sign the extraction is broken rather than the document being short", len(named))
	}

	// grep the tree ONCE for every `func TestX(`, including the integration suite, which is behind a
	// build tag and would otherwise look absent.
	out, err := exec.Command("grep", "-rhoE", `^func (Test[A-Za-z0-9_]+)\(`, "../../internal", "../../cmd",
		"../../test").Output()
	if err != nil {
		t.Fatalf("scanning for test functions: %v", err)
	}
	defined := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if n := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), "func "), "("); n != "" {
			defined[n] = true
		}
	}

	var missing []string
	for name := range named {
		if !defined[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the claim surfaces name %d test(s) that do not exist: %s\n"+
			"    The document's claim is that every invariant is backed by a test that FAILS when the "+
			"property regresses. A name that resolves to nothing turns a demonstrated claim into a "+
			"sentence. Rename the reference, or restore the test.", len(missing), strings.Join(missing, ", "))
	}
}
