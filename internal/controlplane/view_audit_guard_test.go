package controlplane_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// D483: THE TWO TABLES CONSOLE-5 INTRODUCED WERE LOAD-BEARING AND UNGUARDED.
//
// `viewAudited` skips five paths on the strength of a table entry saying "the handler records this one",
// and the whole surface is audited by ONE `opRead` variable that ~37 hand-written mounts must each
// remember to pass. Both reviewers of D482 found the same thing independently: delete the recording call
// from `dsarHandler`, or write a mount without `opRead`, and the route is silently unaudited with the
// entire suite green. That is the defect CONSOLE-5 exists to remove, reintroduced inside the mechanism
// that replaced it.
//
// These guards read the source, like the CONSOLE-1 route-closure guard beside them, and for the same
// reason: the thing being asserted is a property of how the code is WRITTEN, and there is no runtime
// moment at which "this handler no longer records" is observable — the route just quietly answers 200.
//
// HONEST LIMIT, stated here rather than discovered later: a source scan proves a recording call is
// PRESENT, not that it runs on every path. A handler could record inside a branch nobody enters. What it
// catches is deletion, which is the failure the reviewers demonstrated; the behavioural cases in
// view_audit_test.go carry the rest for the routes that have them.

// recordingCall matches the ways a handler can record a view.
//
// `s.View(` is included because for `/view` it IS the recording call: View records and then serves in
// one function precisely so a caller cannot obtain the evidence without leaving a record (D56/D20).
var recordingCall = regexp.MustCompile(`recordRequestView\(|RecordView\(|recordViewDetail\(|s\.View\(`)

// namedFuncBody returns the body of `func (s *Server) <name>(`, relying on gofmt: a top-level
// declaration ends at a `}` in column zero, so no brace counting (which string literals break) is needed.
func namedFuncBody(srcs map[string]string, name string) (string, bool) {
	sig := "func (s *Server) " + name + "("
	for _, src := range srcs {
		i := strings.Index(src, sig)
		if i < 0 {
			continue
		}
		if end := strings.Index(src[i:], "\n}\n"); end >= 0 {
			return src[i : i+end], true
		}
		return src[i:], true
	}
	return "", false
}

// enclosingFuncBody returns the top-level function containing the byte offset `idx`.
//
// Needed because one of the five registers its handler as an INLINE closure (`/view`, inside
// ViewHandler), so there is no named function to look up. The granularity is then the whole enclosing
// function, which is the right unit anyway: ViewHandler's recording is `s.View`, one call out.
func enclosingFuncBody(src string, idx int) string {
	start := strings.LastIndex(src[:idx], "\nfunc ")
	if start < 0 {
		start = 0
	}
	end := strings.Index(src[start+1:], "\n}\n")
	if end < 0 {
		return src[start:]
	}
	return src[start : start+1+end]
}

// handlerSourceForRoute finds the handler registered for a path and returns its source.
func handlerSourceForRoute(t *testing.T, srcs map[string]string, path string) (string, bool) {
	t.Helper()
	reg := `mux.HandleFunc("` + path + `", `
	for _, src := range srcs {
		i := strings.Index(src, reg)
		if i < 0 {
			continue
		}
		rest := src[i+len(reg):]
		if strings.HasPrefix(rest, "func(") {
			return enclosingFuncBody(src, i), true
		}
		// A named method value: `s.casesHandler)`.
		name := rest
		if j := strings.IndexAny(name, ")\n"); j >= 0 {
			name = name[:j]
		}
		return namedFuncBody(srcs, strings.TrimPrefix(strings.TrimSpace(name), "s."))
	}
	return "", false
}

// TestEveryInHandlerAuditedRouteActuallyRecords.
//
// `viewAudited` returns early for every path in `viewAuditedInHandler`, unconditionally, because a
// comment says the handler does it better — each of those five knows a subject the URL does not carry.
// Nothing checked that the handler still does it. These are not incidental routes: they are the DSAR,
// a case file, an incident timeline, the view audit itself and a saved hunt — the five highest-
// sensitivity reads on the surface, singled out for the skip precisely because they matter most.
//
// Mutation: delete the recordRequestView call from dsarHandler (or casesHandler, or
// savedSearchRunHandler) → this FAILS naming that route. (Verified.)
func TestEveryInHandlerAuditedRouteActuallyRecords(t *testing.T) {
	srcs := controlplaneSources(t)
	inHandler := controlplane.ViewAuditedInHandlerForTest()
	if len(inHandler) == 0 {
		t.Fatal("the in-handler table is empty — this guard proves nothing")
	}

	var missing, unfound []string
	for path := range inHandler {
		body, ok := handlerSourceForRoute(t, srcs, path)
		if !ok {
			unfound = append(unfound, path)
			continue
		}
		if !recordingCall.MatchString(body) {
			missing = append(missing, path)
		}
	}
	sort.Strings(missing)
	sort.Strings(unfound)

	if len(unfound) > 0 {
		t.Errorf("no registered handler was found for %v — the view audit SKIPS these paths on the "+
			"strength of the claim that their handler records, and this guard cannot even locate the "+
			"handler, so nobody is checking that claim", unfound)
	}
	if len(missing) > 0 {
		t.Errorf("the view audit skips %v because their handler is said to record the view, and that "+
			"handler contains no recording call. The route is unaudited AND looks accounted for, which "+
			"is strictly worse than the gap CONSOLE-5 closed: the table asserts a decision somebody "+
			"made, against code that stopped honouring it", missing)
	}
}

// mountLine matches a mount on the served TLS mux, keeping the whole line so the wrapper can be seen.
var mountLine = regexp.MustCompile(`(?m)^\s*mux\.Handle\((.*)$`)

// viewAuditMountExempt are mounts that legitimately do NOT pass the audited handler, with the reason.
//
// Same discipline as viewAuditExempt: not passing the audit is the case that costs somebody a sentence.
// A stale entry fails too — an exemption naming a mount that no longer exists reads as a considered
// decision while applying to nothing.
var viewAuditMountExempt = map[string]string{
	`"/enroll"`: "the AGENT onboarding route, gated on the agent role rather than an operator tier — " +
		"there is no operator principal on the request and nothing here is a read of anyone's data",
	`"/view"`: "mounted with its own handler, which records the view itself (D56) — it is in " +
		"viewAuditedInHandler, and TestEveryInHandlerAuditedRouteActuallyRecords is what holds it there",
	`scimUsers`: "the identity provider's deprovisioning hook, authenticated with its OWN token and " +
		"deliberately not behind an operator tier (ZT-7) — it is a write by a machine, not an " +
		"operator read, and there is no operator identity to attribute one to",
	`scimUsers+"/"`: "the same SCIM hook's subtree mount; see the entry above",
}

// TestEveryOperatorMountPassesTheViewAudit.
//
// The audit is applied ONCE, to a variable, which ~37 mounts then share by remembering to pass it.
// `mux.Handle("/export", s.requireTier(RoleAnalyst, s.exportHandler()))` is a perfectly ordinary line
// that is completely unaudited, and every guard in this package passes against it — the route-closure
// guard included, because it IS registered and it IS mounted. CONSOLE-28 is bulk export, which is
// "scroll the fleet and leave nothing" with a download button, and it is the next ticket.
//
// Mutation: change any mount to pass `s.OperatorReadHandler()` instead of `opRead` → this FAILS naming
// it. Mutation: delete an allowlist entry → that mount FAILS. (Both verified.)
func TestEveryOperatorMountPassesTheViewAudit(t *testing.T) {
	srcs := controlplaneSources(t)
	outer, ok := srcs["enroll_http.go"]
	if !ok {
		t.Fatal("enroll_http.go not found — this guard is scanning the wrong directory")
	}

	seen := map[string]bool{}
	var unaudited []string
	audited := 0
	for _, m := range mountLine.FindAllStringSubmatch(outer, -1) {
		arg := m[1]
		if i := strings.Index(arg, ","); i >= 0 {
			arg = arg[:i]
		}
		arg = strings.TrimSpace(arg)
		seen[arg] = true
		if strings.Contains(m[1], "opRead") {
			audited++
			continue
		}
		if reason, exempt := viewAuditMountExempt[arg]; exempt {
			if len(reason) < 40 {
				t.Errorf("%s is exempt from the view audit with a reason too thin to disagree with: %q",
					arg, reason)
			}
			continue
		}
		unaudited = append(unaudited, arg)
	}

	// NOT VACUOUS. If the pattern stops matching, every assertion above is trivially satisfied — which is
	// exactly how a guard becomes a comment.
	if audited < 20 {
		t.Fatalf("only %d mounts were seen to pass the view audit; the operator surface is larger than "+
			"that, so this pattern no longer matches the code and the guard proves nothing", audited)
	}
	sort.Strings(unaudited)
	if len(unaudited) > 0 {
		t.Errorf("mounted on the operator surface WITHOUT passing through the view audit: %v\nA read "+
			"reachable at an operator tier that leaves no record is the gap CONSOLE-5 closed; the audit "+
			"is applied by one variable that every mount has to remember, so a mount written without it "+
			"is unaudited and nothing else in this package notices", unaudited)
	}
	for arg := range viewAuditMountExempt {
		if !seen[arg] {
			t.Errorf("%s is exempted from the view audit and is not a mount that exists — the exemption "+
				"applies to nothing while reading as though somebody considered it", arg)
		}
	}
}
