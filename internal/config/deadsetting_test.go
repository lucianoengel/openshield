package config_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/config"
)

// EVERY DECLARED SETTING MUST HAVE A READER (D333).
//
// The package doc says a derived schema makes it "structurally impossible" for a surface to offer a
// field the binary never reads. Derivation delivers that for a field the code NEVER HAD. It does not
// cover a field whose reader was later DELETED — and that happened twice, undetected:
//
//   - OPENSHIELD_POSTURE_PUBKEY outlived SEC-12, which replaced one fleet-wide posture key with a
//     per-agent roster precisely because a shared key let any agent forge another's posture. The gateway
//     stopped reading it; the declaration stayed, so the surface kept offering it.
//   - OPENSHIELD_NOTIFY_DEDUPE_RETENTION was never read at all, while the prune it names ran on a
//     hardcoded 24 hours AND recorded a compliance event asserting the setting's name. An operator who
//     set 7d had their value ignored and an audit record citing their knob with someone else's value.
//
// `TestEveryEnvReadIsDeclared` checks the other direction and explicitly declines this one, for a good
// reason: a binary's configuration surface includes what its LIBRARIES read, so a command-scoped reverse
// check would flag OPENSHIELD_POLICY_PACK and OPENSHIELD_JETSTREAM as dead. That reasoning settles the
// per-binary question and leaves a different one open — is this key read AT ALL, anywhere? — which is
// module-scoped, has a definite answer, and is exactly the dead-setting question.

// declKey matches a field declaration.
var declKey = regexp.MustCompile(`\{Key: "(OPENSHIELD_[A-Z0-9_]+)"`)

// stripGoComments removes // and /* */ comments.
//
// NOT AN OPTIMISATION — the comment IS the symptom. OPENSHIELD_POSTURE_PUBKEY appears in the gateway's
// source inside a comment explaining that the gateway no longer reads it, so a naive text search finds
// it and concludes it is alive. Prose documenting a retirement is the strongest evidence a setting is
// dead; treating it as a reader would have hidden the exact case this exists to catch.
func stripGoComments(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	lines := strings.Split(src, "\n")
	for i, ln := range lines {
		if j := strings.Index(ln, "//"); j >= 0 {
			lines[i] = ln[:j]
		}
	}
	return strings.Join(lines, "\n")
}

func TestEveryDeclaredSettingIsReadSomewhere(t *testing.T) {
	root := filepath.Join("..", "..")

	declared := map[string]bool{}
	declFiles := map[string]bool{}
	var body strings.Builder
	scanned := 0

	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "node_modules", "bin", "openspec", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		src := string(b)
		if m := declKey.FindAllStringSubmatch(src, -1); m != nil {
			declFiles[p] = true
			for _, g := range m {
				declared[g[1]] = true
			}
			return nil // a declaration is not a read
		}
		scanned++
		body.WriteString(stripGoComments(src))
		body.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(declared) == 0 || scanned == 0 {
		t.Fatal("scanned no declarations or no source — this guard would pass on an empty tree")
	}

	readers := body.String()
	var dead []string
	for key := range declared {
		if !strings.Contains(readers, `"`+key+`"`) {
			dead = append(dead, key)
		}
	}
	if len(dead) > 0 {
		t.Errorf("%d declared setting(s) are read by NOTHING (comments stripped, tests excluded): %v\n"+
			"An operator-visible field that does nothing is the failure the derived schema exists to "+
			"prevent — the form offers it, they set it, nothing happens. Either give it a reader or "+
			"remove it; which one is a judgement this check cannot make for you", len(dead), dead)
	}
}

// TestTheDeadSettingGuardIgnoresComments is the mutation, held permanently.
//
// Without comment-stripping the guard passes on a setting whose only appearance is the prose explaining
// why it was retired — which is precisely the shape both real findings had.
func TestTheDeadSettingGuardIgnoresComments(t *testing.T) {
	const src = `package x
// OPENSHIELD_RETIRED_SETTING used to be read here; SEC-12 replaced it.
func f() { _ = os.Getenv("OPENSHIELD_LIVE_SETTING") }`
	stripped := stripGoComments(src)
	if strings.Contains(stripped, "OPENSHIELD_RETIRED_SETTING") {
		t.Error("a setting named only in a comment survived stripping, so prose documenting a retirement " +
			"would count as a reader — the exact case this guard exists to catch")
	}
	if !strings.Contains(stripped, `"OPENSHIELD_LIVE_SETTING"`) {
		t.Error("a genuine read was stripped")
	}
}

// TestALibraryReadCounts: a setting declared for a command but read inside a package it uses is ALIVE.
// Scoping the check to the command would flag it, which is why the existing per-command guard declines
// the reverse direction and why this one is module-wide.
func TestALibraryReadCounts(t *testing.T) {
	for _, key := range []string{"OPENSHIELD_POLICY_PACK", "OPENSHIELD_JETSTREAM"} {
		found := false
		for _, fs := range [][]config.Field{config.ServerFields, config.GatewayFields, config.EngineFields,
			config.AgentFields, config.WorkerFields, config.FleetAgentFields} {
			for _, f := range fs {
				if f.Key == key {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s is no longer declared — this fixture is meant to pin the library-read case", key)
		}
	}
}
