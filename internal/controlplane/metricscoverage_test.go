package controlplane_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// A COUNTER THAT NOTHING RENDERS IS WORSE THAN NO COUNTER, and this package has now shipped that defect
// twice.
//
// metrics.go already carries the record of the first time: the CEF/CloudTrail/WEF ingest counters "were
// incremented from the day they were written and rendered by nothing — while a comment beside them claimed
// they were already on /metrics and that dashboards depended on them." Eleven more had accumulated since,
// most of them FAILURE counters: playbook failures, correlation failures, ITSM failures, approval-expiry
// failures, consumer-repair failures. Each incremented a number no operator could read.
//
// The failure mode is specific and it is why a guard is worth more than the fix. A counter looks present
// in the code — it is declared, it is incremented at the right moment, its comment explains why it matters
// — and every one of those things is true while the value goes nowhere. Nothing fails. The only symptom is
// that the "never silent" property the product claims is quietly absent for that signal.
//
// So: every atomic counter declared in this package must be READ by metrics.go, or be listed below with a
// reason. The allowlist is checked for staleness too, so an entry cannot outlive the counter it excuses.

// renderedElsewhere maps a counter's declared name to why metrics.go does not name it directly. A counter
// fronted by an accessor is rendered through that accessor; the guard cannot see through the call, so the
// reason records which one.
//
// ONE ENTRY IS NOT A COUNTER AT ALL. `backfilling` is an atomic.Int64 used as a re-entrant flag — the
// depth of nested backfill runs — and rendering "how many backfills are in flight" as a metric would be
// reporting an implementation detail as an operational signal. It is here because the guard matches on
// TYPE (atomic.Int64) rather than on intent, which is the right trade: catching a real metric that nobody
// renders matters more than never asking about a flag, and the alternative is a guard that can be evaded
// by choosing a name. The cost is this comment, once.
var renderedElsewhere = map[string]string{
	"repairs":             "ingestHealth field, rendered via s.IngestRepairs()",
	"failed":              "ingestHealth field, rendered via s.IngestRepairFailures()",
	"scimProvisioned":     "package var, rendered via ScimProvisioned()",
	"scimDeprovisioned":   "package var, rendered via ScimDeprovisioned()",
	"operatorRoleChanges": "package var, rendered via OperatorRoleChanges()",
	"skewedEvents":        "package var, rendered via SkewedEvents()",
	"backfilling":         "NOT a metric: a re-entrant flag counting in-flight backfill runs (SOAR-10), read by quiet()",
}

func TestEveryCounterReachesTheMetricsEndpoint(t *testing.T) {
	const dir = "."
	metrics, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatalf("reading metrics.go: %v", err)
	}
	rendered := string(metrics)

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing the package: %v", err)
	}

	declared := map[string]string{} // counter name -> file it was declared in
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch d := n.(type) {
				case *ast.ValueSpec: // package-level or local: var X atomic.Int64
					if isAtomicCounter(d.Type) {
						for _, name := range d.Names {
							declared[name.Name] = path
						}
					}
				case *ast.Field: // struct field: X atomic.Int64
					if isAtomicCounter(d.Type) {
						for _, name := range d.Names {
							declared[name.Name] = path
						}
					}
				}
				return true
			})
		}
	}

	if len(declared) < 10 {
		t.Fatalf("only %d atomic counters found; the parse is not seeing the package and this guard would "+
			"pass vacuously", len(declared))
	}

	var missing []string
	for name, file := range declared {
		if _, excused := renderedElsewhere[name]; excused {
			continue
		}
		// Word-boundary-ish check: the counter must be named in metrics.go.
		if !strings.Contains(rendered, name+".Load()") && !strings.Contains(rendered, name+"()") {
			missing = append(missing, name+"  (declared in "+file+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("these counters are incremented but NEVER RENDERED on /metrics:\n  %s\n\n"+
			"A counter nothing reads gives the appearance of the product's 'never silent' property and "+
			"none of its substance, and the failure is invisible precisely because the counter looks "+
			"present in the code. Add it to the metrics rendering, or to renderedElsewhere with the "+
			"accessor that renders it.", strings.Join(missing, "\n  "))
	}

	// A STALE ALLOWLIST IS ITS OWN BUG. An entry that outlives its counter silently excuses a name that
	// may later be reused for something that genuinely is unrendered.
	var stale []string
	for name := range renderedElsewhere {
		if _, ok := declared[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("renderedElsewhere excuses counters that no longer exist: %s\n"+
			"Remove them, or the next counter to take one of those names is excused for free.",
			strings.Join(stale, ", "))
	}
}

// isAtomicCounter reports whether a type expression is atomic.Int64 or atomic.Uint64.
func isAtomicCounter(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "atomic" {
		return false
	}
	return sel.Sel.Name == "Int64" || sel.Sel.Name == "Uint64"
}
