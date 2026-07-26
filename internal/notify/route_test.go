package notify_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/lucianoengel/openshield/internal/notify"
)

// SOAR-9: the routing table.
//
// The property that shapes the design is EXCLUSIVITY — "critical goes to the pager and nowhere else" —
// which a union-of-all-matching-rules semantic cannot express. Hence first-match-wins.

type recordingSink struct {
	mu   sync.Mutex
	got  []notify.Notification
	fail error
}

func (r *recordingSink) Notify(_ context.Context, n notify.Notification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, n)
	return r.fail
}

func (r *recordingSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

// routerFixture is the roadmap's acceptance shape: two sinks, and a table that sends critical to the
// pager only and everything else to chat.
func routerFixture() (*notify.Router, *recordingSink, *recordingSink) {
	pager, chat := &recordingSink{}, &recordingSink{}
	return &notify.Router{
		Sinks: map[string]notify.Notifier{"pager": pager, "chat": chat},
		Routes: []notify.Route{
			{MinSeverity: "critical", Sinks: []string{"pager"}},
			{MinSeverity: "low", Sinks: []string{"chat"}},
		},
	}, pager, chat
}

// TestCriticalRoutesToThePagerOnly is SOAR-9's acceptance case.
//
// Mutation: deliver to the union of ALL matching rules instead of the first → the critical notification
// also reaches chat → FAILS. That mutation is the whole reason the semantic is first-match-wins: both
// rules match a critical notification, and a union cannot express "pager only".
func TestCriticalRoutesToThePagerOnly(t *testing.T) {
	r, pager, chat := routerFixture()
	ctx := context.Background()

	if err := r.Notify(ctx, notify.Notification{Kind: notify.KindIncident, Severity: "critical"}); err != nil {
		t.Fatal(err)
	}
	if pager.count() != 1 {
		t.Errorf("pager received %d, want 1", pager.count())
	}
	if chat.count() != 0 {
		t.Errorf("chat received %d critical notification(s), want 0 — the pager rule is not exclusive, so "+
			"every critical page also goes everywhere a broader rule points", chat.count())
	}

	// And the reverse: informational goes to chat only, so the pager keeps meaning something.
	if err := r.Notify(ctx, notify.Notification{Kind: notify.KindPeerAlert, Severity: "low"}); err != nil {
		t.Fatal(err)
	}
	if chat.count() != 1 {
		t.Errorf("chat received %d low-severity notification(s), want 1", chat.count())
	}
	if pager.count() != 1 {
		t.Errorf("the pager received a low-severity notification (%d total, want 1) — this is how a pager "+
			"gets muted, and then the page that mattered is muted too", pager.count())
	}
	if got := r.Unrouted.Load(); got != 0 {
		t.Errorf("unrouted = %d, want 0 — both notifications matched a rule", got)
	}
}

// TestKindConstrainedRuleDoesNotMatchAnotherKind
func TestKindConstrainedRuleDoesNotMatchAnotherKind(t *testing.T) {
	pager, chat := &recordingSink{}, &recordingSink{}
	r := &notify.Router{
		Sinks: map[string]notify.Notifier{"pager": pager, "chat": chat},
		Routes: []notify.Route{
			{Kinds: []notify.Kind{notify.KindApprovalPending}, Sinks: []string{"pager"}},
			{Kinds: []notify.Kind{notify.KindIncident}, Sinks: []string{"chat"}},
		},
	}
	if err := r.Notify(context.Background(), notify.Notification{Kind: notify.KindIncident, Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	if pager.count() != 0 || chat.count() != 1 {
		t.Errorf("kind routing sent pager=%d chat=%d, want 0 and 1", pager.count(), chat.count())
	}
}

// TestUnmatchedGoesEverywhereAndIsCounted — the fail-open.
//
// Dropping an unmatched notification, or sending it to a "default", both fail identically: a table with a
// hole silently stops delivering exactly the notifications that fit no rule, and those are
// disproportionately likely to be the novel ones.
//
// Mutation: drop the unmatched notification instead of fanning out → FAILS.
// Mutation: fan out but do not count → FAILS.
func TestUnmatchedGoesEverywhereAndIsCounted(t *testing.T) {
	pager, chat := &recordingSink{}, &recordingSink{}
	r := &notify.Router{
		Sinks:  map[string]notify.Notifier{"pager": pager, "chat": chat},
		Routes: []notify.Route{{Kinds: []notify.Kind{notify.KindApprovalPending}, Sinks: []string{"pager"}}},
	}
	// An incident matches no rule at all.
	if err := r.Notify(context.Background(), notify.Notification{Kind: notify.KindIncident, Severity: "critical"}); err != nil {
		t.Fatal(err)
	}
	if pager.count() != 1 || chat.count() != 1 {
		t.Errorf("an unmatched notification reached pager=%d chat=%d, want 1 each — a routing table with a "+
			"hole must not swallow alerts", pager.count(), chat.count())
	}
	if got := r.Unrouted.Load(); got != 1 {
		t.Errorf("unrouted counter = %d, want 1 — the fail-open is invisible, so a misconfigured table "+
			"looks exactly like a quiet fleet", got)
	}

	// A notification with NO severity cannot satisfy a severity floor, and must fall through to the
	// fail-open rather than being silently discarded by a rule it half-matched.
	r2, pager2, chat2 := routerFixture()
	if err := r2.Notify(context.Background(), notify.Notification{Kind: notify.KindIncident}); err != nil {
		t.Fatal(err)
	}
	if pager2.count() != 1 || chat2.count() != 1 || r2.Unrouted.Load() != 1 {
		t.Errorf("a severity-less notification went pager=%d chat=%d unrouted=%d, want 1/1/1",
			pager2.count(), chat2.count(), r2.Unrouted.Load())
	}
}

// TestOneFailingSinkDoesNotSuppressTheOther preserves SIEM-8's fanout guarantee through the router.
func TestOneFailingSinkDoesNotSuppressTheOther(t *testing.T) {
	broken := &recordingSink{fail: errors.New("sink down")}
	healthy := &recordingSink{}
	r := &notify.Router{
		Sinks:  map[string]notify.Notifier{"broken": broken, "healthy": healthy},
		Routes: []notify.Route{{Sinks: []string{"broken", "healthy"}}},
	}
	err := r.Notify(context.Background(), notify.Notification{Kind: notify.KindIncident, Severity: "high"})
	if err == nil {
		t.Error("a failing sink reported success")
	}
	if healthy.count() != 1 {
		t.Errorf("the healthy sink received %d, want 1 — one broken sink suppressed delivery to a working "+
			"one", healthy.count())
	}
}

// TestRuleNamingAnUnconfiguredSinkStillDelivers: a stale rule must not swallow the notification.
func TestRuleNamingAnUnconfiguredSinkStillDelivers(t *testing.T) {
	chat := &recordingSink{}
	r := &notify.Router{
		Sinks:  map[string]notify.Notifier{"chat": chat},
		Routes: []notify.Route{{Sinks: []string{"gone", "chat"}}},
	}
	err := r.Notify(context.Background(), notify.Notification{Kind: notify.KindIncident, Severity: "high"})
	if chat.count() != 1 {
		t.Errorf("chat received %d, want 1 — a rule naming a missing sink suppressed a live one", chat.count())
	}
	if err == nil || !strings.Contains(err.Error(), "gone") {
		t.Errorf("the missing sink was not reported: %v", err)
	}
	if r.MissingSink.Load() != 1 {
		t.Errorf("missing-sink counter = %d, want 1", r.MissingSink.Load())
	}
}

// TestRoutingTableIsValidatedAtLoad — a routing mistake found at delivery time is found by an alert not
// arriving.
func TestRoutingTableIsValidatedAtLoad(t *testing.T) {
	sinks := []string{"pager", "chat"}
	for _, tc := range []struct{ name, cfg string }{
		{"unknown severity", `[{"min_severity":"urgent","sinks":["pager"]}]`},
		{"unknown kind", `[{"kinds":["page-the-ceo"],"sinks":["pager"]}]`},
		{"no sinks", `[{"min_severity":"critical","sinks":[]}]`},
		{"unconfigured sink", `[{"min_severity":"critical","sinks":["sms"]}]`},
		{"unknown field", `[{"min_severity":"critical","sinks":["pager"],"subject":"agent-1"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := notify.LoadRoutes(strings.NewReader(tc.cfg), sinks); err == nil {
				t.Errorf("%s was accepted", tc.name)
			}
		})
	}
	ok := `[{"kinds":["incident"],"min_severity":"critical","sinks":["pager"]},{"sinks":["chat"]}]`
	routes, err := notify.LoadRoutes(strings.NewReader(ok), sinks)
	if err != nil {
		t.Fatalf("a valid table was refused: %v", err)
	}
	if len(routes) != 2 || routes[0].Sinks[0] != "pager" || routes[1].Sinks[0] != "chat" {
		t.Fatalf("declared order was not preserved: %+v", routes)
	}
}

// TestRouteSelectsOnKindAndSeverityOnly.
//
// Deliberately no subject/entity selector: a rule keyed on a subject would put a pseudonymous identifier
// (D23) into a table an operator reads and edits, and would let one person's alerts be routed somewhere
// nobody looks.
func TestRouteSelectsOnKindAndSeverityOnly(t *testing.T) {
	want := []string{"Kinds", "MinSeverity", "Sinks"}
	typ := reflect.TypeOf(notify.Route{})
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Route fields = %v, want exactly %v. Routing must not select on a subject, entity or "+
			"agent: that is a re-identification surface and a way to route one person's alerts out of "+
			"sight.", got, want)
	}
}

func TestSeverityRankIsAClosedVocabulary(t *testing.T) {
	prev := -1
	for _, s := range []string{"low", "medium", "high", "critical"} {
		r, ok := notify.SeverityRank(s)
		if !ok {
			t.Fatalf("%q does not rank", s)
		}
		if r <= prev {
			t.Errorf("%q ranks %d, not above the previous %d", s, r, prev)
		}
		prev = r
	}
	if _, ok := notify.SeverityRank("urgent"); ok {
		t.Error("an unknown severity ranked — the routing vocabulary is not closed")
	}
}
