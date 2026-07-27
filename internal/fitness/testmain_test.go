package fitness_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A TestMain IN A NON-_test.go FILE IS DEAD CODE (D313).
//
// The integration suite's TestMain lived in `harness.go` for four rounds. It tore down the shared Postgres
// container and the build directory, it compiled, it read correctly to every reviewer including me — and
// `go test` never called it, because the testing framework only recognises TestMain in a _test.go file.
// Anywhere else it is an ordinary function with a suggestive name that nothing invokes.
//
// NO TEST COULD HAVE CAUGHT IT, which is what makes it worth a static guard rather than a lesson. The
// function's entire job was to tidy up after the suite; its absence therefore produced exactly zero
// failing assertions, because everything it should have removed is by definition not what the suite
// asserts on. The evidence was on the HOST: 33 abandoned Postgres containers and 130 build directories,
// 25GB, until the root filesystem filled and the build failed to LINK — a red gate whose message
// ("no space left on device") pointed at the machine and not at the mistake.
//
// The shape is checkable in one grep, and the same shape catches its cousins: a `func Test...` or a
// `func Benchmark...` in a non-test file is likewise never run.

var testEntryPoint = regexp.MustCompile(`(?m)^func (TestMain|Test[A-Z]\w*|Benchmark[A-Z]\w*)\s*\(`)

func TestNoTestEntryPointLivesInANonTestFile(t *testing.T) {
	root := filepath.Join("..", "..")
	checked := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "node_modules", "openspec", ".claude":
				return filepath.SkipDir
			}
			return nil
		}
		// A _test.go file is where these belong; everything else is suspect.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		checked++
		for _, m := range testEntryPoint.FindAllStringSubmatch(string(b), -1) {
			t.Errorf("%s declares %s in a file that is NOT _test.go.\n"+
				"    The testing framework only recognises test entry points in _test.go files, so this "+
				"function is never called. It compiles, it reads like it works, and nothing fails — which "+
				"is exactly how the integration suite spent four rounds leaking a Postgres container and "+
				"196MB of binaries per run. Rename the file to end in _test.go.", path, m[1])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	if checked == 0 {
		t.Fatal("no non-test Go files were examined, so this guard would pass vacuously")
	}
}
