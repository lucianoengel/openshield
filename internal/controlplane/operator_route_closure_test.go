package controlplane_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// CONSOLE-1: A ROUTE REGISTERED ON THE INNER HANDLER AND NOT MOUNTED ON THE TLS MUX IS UNREACHABLE, and
// nothing said so.
//
// The operator surface is built twice. `OperatorReadHandler` registers the handlers; `enroll_http.go`
// mounts each path on the mutual-TLS listener behind `requireTier`. A path present in the first and
// absent from the second is a feature that exists, is tested, and cannot be called — the shape this repo
// has now found in D313, D415, D417, D418 and CONSOLE-1 itself.
//
// The ticket proposed making the route set DATA so the divergence is unrepresentable. This guard is the
// cheaper half of that and is recorded as a deliberate deviation: restructuring how 37 security-gated
// routes are mounted risks landing one at the wrong TIER, which is worse than the drift being guarded
// against — and the tier is already declared exactly once, in the outer mux, so there is no duplication
// to remove there. What was missing is a check that the two sets agree, which is this.
//
// Measured when written: 37 inner, 37 outer, no divergence. `/report/response` — which the roadmap
// listed as registered-but-unmounted — IS mounted at `enroll_http.go:124`; that claim was stale.

// REGISTRATION vs MOUNTING is the distinction, not which file the call is in.
//
// `mux.HandleFunc` attaches a handler function to an inner mux — that is a registration, and
// enroll_http.go contains one of its own (`/enroll`, inside EnrollHandler). `mux.Handle` attaches an
// already-built handler to the outer TLS mux — that is a mounting. Splitting on the file instead of on
// the call reported /enroll as mounted-but-unregistered, which was the guard being wrong rather than
// the code.
var (
	registerCall = regexp.MustCompile(`mux\.HandleFunc\("(/[^"]*)"`)
	mountCall    = regexp.MustCompile(`mux\.Handle\("(/[^"]*)"`)
)

// controlplaneSources returns every non-test source file in the package.
func controlplaneSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(".", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

func matches(re *regexp.Regexp, src string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestEveryRegisteredOperatorRouteIsMountedAndViceVersa.
//
// Mutation: delete any `mux.Handle("/...")` line from enroll_http.go → that path becomes registered and
// unreachable → this FAILS naming it.
func TestEveryRegisteredOperatorRouteIsMountedAndViceVersa(t *testing.T) {
	srcs := controlplaneSources(t)
	outerSrc, ok := srcs["enroll_http.go"]
	if !ok {
		t.Fatal("enroll_http.go not found — this guard is scanning the wrong directory")
	}

	mounted := map[string]bool{}
	for _, p := range matches(mountCall, outerSrc) {
		mounted[p] = true
	}
	registered := map[string]bool{}
	for _, src := range srcs {
		for _, p := range matches(registerCall, src) {
			registered[p] = true
		}
	}

	if len(registered) == 0 || len(mounted) == 0 {
		t.Fatalf("found %d registered and %d mounted routes — the patterns no longer match the code, so "+
			"this guard proves nothing", len(registered), len(mounted))
	}

	var unreachable, unregistered []string
	for p := range registered {
		if !mounted[p] {
			unreachable = append(unreachable, p)
		}
	}
	for p := range mounted {
		if !registered[p] {
			unregistered = append(unregistered, p)
		}
	}
	sort.Strings(unreachable)
	sort.Strings(unregistered)

	if len(unreachable) > 0 {
		t.Errorf("registered on the operator handler and NOT mounted on the TLS mux, so no client can "+
			"reach them: %v\nA handler that exists, passes its tests and cannot be called is "+
			"indistinguishable from one that was never written — and worse, because the tests say it "+
			"works", unreachable)
	}
	if len(unregistered) > 0 {
		t.Errorf("mounted on the TLS mux with no registered handler, so they answer 404 from behind the "+
			"authentication gate: %v", unregistered)
	}
}
