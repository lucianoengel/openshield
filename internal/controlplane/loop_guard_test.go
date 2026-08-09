package controlplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoLeaderLoopCountsItsOwnFailures is the repo-wide guard behind the stop rule.
//
// ONE LEXICAL RULE: no `*Failures.Add(...)` may appear inside a `retain.Loop` / `retain.DynamicLoop`
// function literal, anywhere in the tree. Counting is NoteTickErr's job, and a direct increment in a loop
// body is by definition a site that bypassed the decision.
//
// WHY LEXICAL RATHER THAN SEMANTIC. The obvious guard — "check each loop guards its increment" — has to
// reason about the polarity of a hand-written conditional AND about which context it reads, and one that
// does not do both accepts `if stopping(err) { count }` (inverted) and `if !isLoopStop(c, err)` (keyed on
// the per-tick context) as compliant. That would have left the requirement unfalsifiable at six of the
// seven loops it was written for. Moving the decision into one helper collapses the check to "no counter
// increments inside a loop body at all", which has no polarity to misread.
//
// REPO-WIDE, not package-scoped, because the seventh loop is in `cmd/openshield-server`. A guard scoped to
// this package would have reported green on the day the universal requirement was violated.
//
// THE CHECK IS NOT EXHAUSTIVE, AND THE SPEC SAYS SO. It sees an increment inside a loop's work function.
// An increment inside a method CALLED FROM that function is equally bound by the requirement and is
// invisible here — `RecordRetentionEvent` is exactly that case, and it was found by review, not by this
// test. The obligation is universal; the build-time check is not.
//
// Mutation A: reintroduce `BeaconFailures.Add(1)` inside RunBeaconLoop's literal → FAILS, naming it.
// Mutation B: revert cmd/openshield-server's retention callback to a bare `RetentionPurgeFailures.Add(1)`
// inside the loop literal → FAILS, proving the walk really leaves internal/controlplane.
// Mutation C: point the walk at an empty directory → FAILS with "did not run", rather than passing.
func TestNoLeaderLoopCountsItsOwnFailures(t *testing.T) {
	root := repoRoot(t)

	loops, increments, violations := scanForLoopCounters(t, root)

	// A GUARD THAT CAN PASS BY FINDING NOTHING IS NOT A GUARD. If a refactor moves the loop helper, or
	// this walk is pointed somewhere wrong, the honest outcome is "the check did not happen" — not a
	// green tick. Precedent: metrics_guard_test.go's TestEveryDeclaredCounterIsExposedOnMetrics.
	if loops == 0 {
		t.Fatalf("the guard scanned %s and found NO retain.Loop/retain.DynamicLoop call sites at all. "+
			"The check did not run. Either the walk is pointed at the wrong tree or the loop helper "+
			"was renamed — fix the guard rather than accepting a pass it did not earn.", root)
	}
	if increments == 0 {
		t.Fatalf("the guard scanned %s and found NO *Failures.Add call sites anywhere. The check did not "+
			"run: there is nothing for it to have rejected, so its passing means nothing.", root)
	}

	for _, v := range violations {
		t.Errorf("%s: %s increments %s INSIDE a %s work function.\n"+
			"A scheduled loop must not decide for itself whether a failing tick counts: on a lost "+
			"leadership or a shutdown the tick's error IS the loop's own cancellation, and counting it "+
			"raises an alarm whose published meaning is that the work is broken. Route it through "+
			"controlplane.NoteTickErr(ctx, log, msg, &%s, err), passing the LOOP's context.",
			v.pos, v.enclosing, v.counter, v.loopFn, v.counter)
	}
	t.Logf("guard scanned %d retain loop call site(s) and %d *Failures.Add site(s) under %s",
		loops, increments, root)
}

type loopViolation struct {
	pos       string
	enclosing string
	counter   string
	loopFn    string
}

// repoRoot walks UP from the package directory to the directory holding go.mod. `go test` sets CWD to the
// package being tested, so a relative "." here would scan one package — which is the scoping bug this
// guard exists to not have.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod found above %s — the guard cannot locate the repository root", dir)
		}
		dir = parent
	}
}

// scanForLoopCounters parses every non-test .go file under root and reports the counts and any violation.
func scanForLoopCounters(t *testing.T, root string) (loops, increments int, violations []loopViolation) {
	t.Helper()
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// HIDDEN DIRECTORIES ARE NOT THIS MODULE. `.claude/worktrees/` holds other agent sessions'
			// git worktrees — whole copies of this repository, nested inside it. Scanning them made the
			// guard report 19 loop sites instead of 14 and would let a sibling session's uncommitted
			// work fail this build, or hide a violation behind an old copy that still looks compliant.
			// `.git` and `.gitnexus` are excluded by the same rule.
			if name := d.Name(); name != "." && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			switch d.Name() {
			case "vendor", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		// Test files are excluded: a test may legitimately drive a counter directly.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil // not parseable as Go; not this guard's business
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if isFailureCounterAdd(call) != "" {
				increments++
			}
			name := retainLoopName(call)
			if name == "" {
				return true
			}
			loops++
			// The work function is the LAST argument. It is not always a literal —
			// internal/posture/attestloop.go passes a named func value (`attempt`) — and a walk that
			// type-asserts *ast.FuncLit unconditionally panics on it. A non-literal is skipped: there
			// is no body here to inspect.
			lit, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
			if !ok {
				return true
			}
			ast.Inspect(lit.Body, func(inner ast.Node) bool {
				ic, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				if counter := isFailureCounterAdd(ic); counter != "" {
					violations = append(violations, loopViolation{
						pos:       trimRoot(root, fset.Position(ic.Pos()).String()),
						enclosing: enclosingFuncName(file, ic.Pos()),
						counter:   counter,
						loopFn:    name,
					})
				}
				return true
			})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return loops, increments, violations
}

// retainLoopName returns "retain.Loop" / "retain.DynamicLoop" for a call to one of them, else "".
func retainLoopName(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) == 0 {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "retain" {
		return ""
	}
	if sel.Sel.Name == "Loop" || sel.Sel.Name == "DynamicLoop" {
		return "retain." + sel.Sel.Name
	}
	return ""
}

// isFailureCounterAdd returns the counter's name for `X.Add(…)` where X is an identifier or selector
// ending in "Failures", else "". That covers both the package-level counters (`BeaconFailures.Add`) and
// the Server fields (`srv.RetentionPurgeFailures.Add`).
func isFailureCounterAdd(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Add" {
		return ""
	}
	switch x := sel.X.(type) {
	case *ast.Ident:
		if strings.HasSuffix(x.Name, "Failures") {
			return x.Name
		}
	case *ast.SelectorExpr:
		if strings.HasSuffix(x.Sel.Name, "Failures") {
			return x.Sel.Name
		}
	}
	return ""
}

// enclosingFuncName names the function or method a position sits in, so a failure points somewhere.
func enclosingFuncName(file *ast.File, pos token.Pos) string {
	name := "<file scope>"
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || pos < fn.Pos() || pos > fn.End() {
			continue
		}
		name = fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			name = "(receiver)." + name
		}
	}
	return name
}

func trimRoot(root, pos string) string {
	return strings.TrimPrefix(strings.TrimPrefix(pos, root), string(filepath.Separator))
}
