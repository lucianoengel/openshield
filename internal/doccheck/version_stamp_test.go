package doccheck_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE RELEASE VERSION STAMP, GUARDED.
//
// `scripts/release.sh` built every artifact with `-ldflags "-X main.version=$VERSION"` and no
// `cmd/*/main.go` ever declared a package-level `version`. The Go linker SILENTLY IGNORES an -X target
// that does not exist — it is not a warning and not an error — so the flag was decorative from the day it
// was written and every shipped OpenShield binary reported no version at all.
//
// That is the worst shape a build-system bug can take: the command succeeds, the artifact is produced,
// the manifest records a version, and the binary knows nothing. Nothing observable fails.
//
// So the coupling between the script and the source is asserted here rather than trusted. A rename or a
// move of the variable now fails a test instead of quietly un-stamping the fleet.

// TestTheReleaseVersionSymbolExists.
//
// Mutation: point VERSION_SYMBOL at a package or variable that does not exist → this FAILS. That is the
// exact state the repository shipped in.
func TestTheReleaseVersionSymbolExists(t *testing.T) {
	const root = "../.."
	script, err := os.ReadFile(filepath.Join(root, "scripts", "release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	symbol := versionSymbol(t, string(script))

	// "example.com/mod/internal/buildinfo.Version" → package path + variable name.
	dot := strings.LastIndex(symbol, ".")
	if dot < 0 {
		t.Fatalf("VERSION_SYMBOL %q is not <package path>.<Variable>", symbol)
	}
	pkgPath, varName := symbol[:dot], symbol[dot+1:]

	const module = "github.com/lucianoengel/openshield/"
	if !strings.HasPrefix(pkgPath, module) {
		t.Fatalf("VERSION_SYMBOL %q is outside this module — the linker would ignore it in silence, "+
			"which is precisely how the previous `main.version` target stamped nothing for its whole life",
			symbol)
	}
	dir := filepath.Join(root, strings.TrimPrefix(pkgPath, module))

	if !declaresVar(t, dir, varName) {
		t.Fatalf("scripts/release.sh stamps %q and no such package-level variable exists in %s.\n"+
			"The Go linker does NOT report an unknown -X target: the build succeeds, the release is "+
			"produced, and every binary in it carries no version. Either add the variable or fix the "+
			"symbol — do not leave the flag pointing at nothing.", symbol, dir)
	}
}

// versionSymbol pulls the stamped symbol out of the script, and fails if the script no longer stamps one
// at all — otherwise deleting the -ldflags line would make this test pass by having nothing to check.
func versionSymbol(t *testing.T, script string) string {
	t.Helper()
	var symbol string
	for _, line := range strings.Split(script, "\n") {
		if m := regexp.MustCompile(`^VERSION_SYMBOL="([^"]+)"`).FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			symbol = m[1]
		}
	}
	if symbol == "" {
		t.Fatal("scripts/release.sh declares no VERSION_SYMBOL — either the release stopped stamping a " +
			"version, or it went back to stamping one this guard cannot see")
	}
	if !strings.Contains(script, "-X $VERSION_SYMBOL=$VERSION") {
		t.Errorf("VERSION_SYMBOL is declared and not used in the -ldflags line — the symbol this test " +
			"verifies is not the one the linker is given")
	}
	return symbol
}

// declaresVar reports whether the package in dir declares a package-level var of that name.
func declaresVar(t *testing.T, dir, name string) bool {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", dir, err)
	}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, id := range vs.Names {
						if id.Name == name {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
