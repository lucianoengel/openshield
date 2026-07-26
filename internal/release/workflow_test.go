package release_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// PLAT-6: the release pipeline's ORDERING is the property worth pinning.
//
// A pipeline that uploads first and verifies afterwards has already distributed whatever it produced, and
// the verification becomes a report rather than a gate. That ordering lives in YAML, where nothing else
// checks it.
//
// Mutation: move the publish step above verification → FAILS.
func TestReleaseWorkflowVerifiesBeforePublishing(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(body)
	verify := strings.Index(wf, "make verify-release")
	publish := strings.Index(wf, "action-gh-release")
	reproduce := strings.Index(wf, "NOT REPRODUCIBLE")
	build := strings.Index(wf, "make release")

	for name, at := range map[string]int{"build": build, "verify": verify,
		"reproducibility check": reproduce, "publish": publish} {
		if at < 0 {
			t.Fatalf("the release workflow has no %s step", name)
		}
	}
	if verify > publish {
		t.Error("the workflow PUBLISHES before it verifies — by then it has already distributed whatever " +
			"it produced, and the verification is a report rather than a gate")
	}
	if reproduce > publish {
		t.Error("the workflow publishes before proving the build reproduces — a release that cannot be " +
			"reproduced would be discovered by someone else, months later")
	}
	if build > verify {
		t.Error("the workflow verifies before it builds")
	}
	// The signing key must not be committed: it is a secret staged into a temp file for one job.
	//
	// Matched on PEM HEADERS only. My first version also flagged the filename appearing near whitespace,
	// which hit the legitimate `chmod 600 .../release.key` line — the third false positive from a
	// text-matching guard in this session, after the config guard matching help text and the wire-version
	// guard matching its own doc comment. The lesson each time: match the THING, not a string that tends
	// to appear near it.
	for _, marker := range []string{"BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN EC PRIVATE KEY"} {
		if strings.Contains(wf, marker) {
			t.Errorf("the workflow embeds key material (%s)", marker)
		}
	}
	if !strings.Contains(wf, "secrets.OPENSHIELD_RELEASE_KEY") {
		t.Error("the signing key does not come from a secret")
	}
}
