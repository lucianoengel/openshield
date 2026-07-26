package core_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
)

// PLAT-9: one wire-version rule, in one place.

func TestAcceptedRangeIncludesWhatWeProduce(t *testing.T) {
	if !core.AcceptsWireVersion(core.WireVersion) {
		t.Fatal("this build does not accept the version it PRODUCES — every consumer would reject its " +
			"own control plane")
	}
	if !core.AcceptsWireVersion(core.MinAcceptedWireVersion) {
		t.Error("the oldest accepted version is not accepted")
	}
	// Rejecting a NEWER version is deliberate: a message from a future publisher may mean something this
	// build would MISAPPLY, and for a containment or a fleet disable, misapplying is worse than ignoring.
	// That is the whole reason consumers must be upgraded before publishers.
	if core.AcceptsWireVersion(core.WireVersion + 1) {
		t.Error("a FUTURE version was accepted — this build would apply a message whose meaning it " +
			"cannot know")
	}
	if core.AcceptsWireVersion(core.MinAcceptedWireVersion - 1) {
		t.Error("a version older than the declared minimum was accepted")
	}
}

// TestNoConsumerHardcodesAWireVersion is the guard that keeps the rule to one home.
//
// There were two hardcoded `GetVersion() != 1` comparisons in different packages before this, and a third
// would eventually disagree with the other two — a version rule spelled in three places is a version rule
// with three answers.
//
// Mutation: reintroduce a literal comparison in a consumer → FAILS.
func TestNoConsumerHardcodesAWireVersion(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	literal := regexp.MustCompile(`GetVersion\(\)\s*[!=]=\s*\d`)
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		// Match CODE, not prose. The first version of this guard flagged wireversion.go itself, because
		// its doc comment QUOTES the pattern it forbids — the same false-positive class that made the
		// config guard match variable names in help text. A guard that reports comments cries wolf.
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if literal.MatchString(line) {
				offenders = append(offenders, path)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("these compare a wire version against a LITERAL instead of core.AcceptsWireVersion: %v\n"+
			"A version rule spelled per package is a version rule with a different answer per package.",
			offenders)
	}
}
