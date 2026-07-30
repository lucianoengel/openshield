package fitness_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// EVERY COUNTER MUST BE READ BY SOMETHING.
//
// This guard exists because the same defect shipped four times, in four packages, over the life of the
// project — and because the guard next door deliberately let it through.
//
// seams_test.go catches "a field you install something into that nothing installs into", and says in its
// own scope note that it excludes "value fields, COUNTERS and decode targets" because including them
// produced a hundred and eighty false positives. That exclusion was the right call for THAT guard and it
// is exactly the blind spot this one covers: a counter is not an uninstalled seam, it is an installed
// thing nobody looks at.
//
// The four:
//
//	SIEM-4/9    the CEF/CloudTrail/WEF ingest counters, "incremented from the day they were written and
//	            rendered by nothing — while a comment beside them claimed they were already on /metrics"
//	D415        eleven more control-plane counters, most of them FAILURE counters
//	D417        core.Metrics.TimedOut — "the cheapest way to detect an adversary manufacturing fail-open
//	            bypasses (D17)" — unreachable, because the dispatcher was in an unexported field
//	D418        every gateway/intent Rejected counter, read ONLY by its own tests, while their comments
//	            said a forged-signature flood "must be observable, not silent"
//
// THE SHAPE IS WHAT MAKES IT INVISIBLE. The counter is declared, incremented at exactly the right moment,
// and carries a comment explaining why it matters. Every one of those is true while the value goes
// nowhere. Nothing fails, no test breaks, and the product's "never silent" property is quietly absent for
// that signal. A test asserting the counter increments — which several had — reads as proof of the
// property and is not: the property is that an OPERATOR can see it.
//
// SCOPE, stated plainly, because a guard that overclaims is worse than none:
//
//   - It checks that a counter is READ somewhere in non-test code. It does NOT check that the read
//     reaches an operator. D417's counter was read by nothing at all, which this catches; a counter read
//     into a variable that is then discarded would pass. That needs a call graph and this is the cheap 90%.
//   - Reads in _test.go files do NOT count. That is the whole point: D418's counters were read only by
//     their own tests, and counting those would have made this guard pass on the exact defect that
//     motivated it.
//   - It covers atomic.Int64 and atomic.Uint64 only. Those are what this codebase counts with.
var sequenceGenerators = map[string]string{
	// Read through Add()'s RETURN VALUE, never Load()ed — they hand out monotonic numbers rather than
	// reporting a quantity. Nothing is missing when nobody reads them.
	"seq":              "sequence generator: the value is Add()'s return, used as the next sequence number",
	"execSeq":          "sequence generator for exec-gate request ids",
	"flowSeq":          "sequence generator for connector flow ids",
	"parseInvocations": "sequence generator: distinguishes parse invocations, not a reported quantity",
}

var (
	counterDecl = regexp.MustCompile(`(?m)^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+atomic\.(?:Int64|Uint64)\s*$`)
	counterRead = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\.Load\b`)
)

func TestEveryCounterIsReadBySomething(t *testing.T) {
	root := filepath.Join("..", "..")

	declared := map[string]string{} // name -> first file that declares it
	read := map[string]bool{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", ".gitnexus", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		// Only the shipped tree. spikes/ are recorded decisions, not product.
		if !strings.HasPrefix(rel, "internal/") && !strings.HasPrefix(rel, "cmd/") {
			return nil
		}
		// Generated protobuf carries its own atomics and is not ours to instrument.
		if strings.HasSuffix(rel, ".pb.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		body := string(src)

		if strings.HasSuffix(rel, "_test.go") {
			// A READ IN A TEST DOES NOT COUNT. D418's counters were read only by their own tests.
			return nil
		}
		for _, m := range counterDecl.FindAllStringSubmatch(body, -1) {
			if _, seen := declared[m[1]]; !seen {
				declared[m[1]] = rel
			}
		}
		for _, m := range counterRead.FindAllStringSubmatch(body, -1) {
			read[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	// A guard that finds nothing to check passes vacuously, which is the failure mode it is here to end.
	if len(declared) < 40 {
		t.Fatalf("only %d counters found; the walk is not seeing the tree and this guard would pass "+
			"without checking anything", len(declared))
	}

	var unread []string
	for name, file := range declared {
		if read[name] {
			continue
		}
		if _, excused := sequenceGenerators[name]; excused {
			continue
		}
		unread = append(unread, name+"  ("+file+")")
	}
	sort.Strings(unread)
	if len(unread) > 0 {
		t.Fatalf("these counters are incremented and READ BY NOTHING outside tests:\n  %s\n\n"+
			"A counter nothing reads gives the appearance of this product's 'never silent' property and "+
			"none of its substance, and it is invisible precisely because the counter LOOKS present in "+
			"the code — declared, incremented at the right moment, with a comment saying why it matters. "+
			"Surface it where its component already reports (/metrics for the control plane, the log "+
			"reporters for the engine and gateway), or add it to sequenceGenerators with the reason it "+
			"is write-only.", strings.Join(unread, "\n  "))
	}

	// A STALE EXCUSE IS ITS OWN BUG: an entry that outlives its counter silently covers the next thing to
	// take that name.
	var stale []string
	for name := range sequenceGenerators {
		if _, ok := declared[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("sequenceGenerators excuses counters that no longer exist: %s", strings.Join(stale, ", "))
	}
}
