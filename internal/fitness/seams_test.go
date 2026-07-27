package fitness_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// EVERY PLUGGABLE SEAM MUST HAVE A PRODUCTION INSTALLER.
//
// D287 found the kill switch, the break-glass watcher, the signed fleet-control channel and the intent
// signer all fully built, fully tested, and reachable from no shipped binary. The switch field on the
// gateway and the engine was nil in every deployment, so `SuppressEnforcement` answered "not suppressed"
// on every call, and the only way to stop OpenShield enforcing was to stop the process — which also stops
// the detection and the audit trail.
//
// The defect had a specific SHAPE, and that shape is checkable: a field you INSTALL something into, that
// nothing installs anything into. `KillSwitch *core.KillSwitch` is the archetype — a pointer or interface
// field on an exported struct, read by the code that would use it, assigned by nobody.
//
// SCOPE, stated plainly, because a guard that overclaims is worse than none:
//
//   - It checks ASSIGNMENT, not REACHABILITY. A field assigned inside internal/ but never reached from a
//     main() would still pass. Proving reachability needs a call graph; this is the cheap 90%.
//   - It looks only at pointer, func and behaviour-interface fields. Value fields, counters and
//     decode targets are data rather than seams, and including them produced a hundred and eighty
//     false positives on the first attempt — enough noise to make the result useless.
//   - It covers exported AND unexported fields. Restricting it to exported ones is what let
//     `Gateway.intents` through.
//
// What it does catch is the exact thing that went wrong, and it costs nothing to run.

// seamField matches a field declaration whose type is a pointer, a func, or one of the behaviour
// interfaces this codebase plugs in. Matched on the DECLARATION, with comments stripped first.
//
// UNEXPORTED FIELDS COUNT TOO, which the first version got wrong and D294 paid for. `Gateway.intents` was
// read on every request and assigned by nothing — and being unexported meant there was not even a SETTER,
// so the branch that consumes a coordinated-response intent was unreachable in every deployment. An
// unexported seam is if anything MORE likely to rot: a missing exported setter is visible to a caller,
// a missing internal assignment is visible to nobody.
var seamField = regexp.MustCompile(
	`^\s+([A-Za-z]\w*)\s+(\*[\w\.]+|func\(|[\w\.]*(?:Notifier|Ledger|Sink|Switch|Store|Applier|Enforcer|Classifier))\s*$`)

var exportedStruct = regexp.MustCompile(`(?s)type ([A-Z]\w+) struct \{(.*?)\n\}`)

// installed matches an assignment or a composite-literal key for the field.
var lineComment = regexp.MustCompile(`(?m)//.*$`)
var blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)

func stripGoComments(src string) string {
	return lineComment.ReplaceAllString(blockComment.ReplaceAllString(src, ""), "")
}

// knownUninstalled are seams deliberately left for a caller inside internal/ to set, with the reason.
//
// An ALLOWLIST WITH REASONS rather than a threshold: "fewer than N" would let the next one in silently,
// which is how this class of defect arrived in the first place.
var knownUninstalled = map[string]string{
	// Set by gateway.New and engine.New from the logger their caller already passes in. There is no
	// deployment in which it is nil and something reads it expecting behaviour.
	"Dispatcher.Logger": "set by the gateway and engine constructors from the caller's logger",
}

func TestEveryPluggableSeamHasAProductionInstaller(t *testing.T) {
	root := filepath.Join("..", "..")

	// Every non-test Go source in the repository, comments stripped.
	sources := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "node_modules", "openspec", ".claude", "corev1":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		sources[path] = stripGoComments(string(b))
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	if len(sources) == 0 {
		t.Fatal("no sources found, so this guard would pass vacuously")
	}

	type seam struct{ file, structName, field string }
	var seams []seam
	for path, src := range sources {
		if !strings.Contains(path, "internal"+string(filepath.Separator)) {
			continue
		}
		for _, m := range exportedStruct.FindAllStringSubmatch(src, -1) {
			for _, line := range strings.Split(m[2], "\n") {
				if f := seamField.FindStringSubmatch(line); f != nil {
					seams = append(seams, seam{path, m[1], f[1]})
				}
			}
		}
	}
	if len(seams) == 0 {
		t.Fatal("no pluggable seams were found, so this guard would pass vacuously")
	}

	for _, s := range seams {
		key := s.structName + "." + s.field
		if _, ok := knownUninstalled[key]; ok {
			continue
		}
		// `Field =` or `Field:` — an assignment or a composite-literal key, anywhere.
		set := regexp.MustCompile(`\b` + regexp.QuoteMeta(s.field) + `\s*[:=][^=]`)
		installed := false
		for _, src := range sources {
			if set.MatchString(src) {
				installed = true
				break
			}
		}
		if !installed {
			t.Errorf("%s is a pluggable seam that NOTHING in production code installs (%s).\n"+
				"    A field the code READS to decide behaviour and nothing ever WRITES is a feature no "+
				"deployment can turn on — its unit tests pass, and every shipped binary behaves as though "+
				"it does not exist. Either wire it in a command, or add it to knownUninstalled WITH THE "+
				"REASON it is set elsewhere.", key, s.file)
		}
	}
}
