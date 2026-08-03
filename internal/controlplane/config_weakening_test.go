package controlplane_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/config"
	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/notify"
)

// SEC-A: a configuration change that reduces detection must not be an ordinary administrative event.
//
// The threat is an operator credential — obtained, not necessarily misused by its owner — being used to
// blind the product before the thing it would have caught. At single-admin tier over POST /config there
// is no four-eyes, no TTL and no sequence, and every value involved is a perfectly valid duration:
// OVERDUE_THRESHOLD=8760h never reports a killed agent, FLEET_RETENTION=1h purges evidence through a
// SANCTIONED delete path the hash chain does not cover.
//
// Bounds refuse the unusable values. They cannot refuse the plausible ones, and this is what covers the
// gap: the change is recorded as weakening and it PAGES SOMEONE, on the channel that already reaches
// whoever is on call. A log line would not do — nobody reads a config-change history at the moment it
// matters.

// all returns a snapshot of everything the shared capturingSink (soar9_test.go) has been handed.
func (c *capturingSink) all() []notify.Notification {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]notify.Notification(nil), c.got...)
}

// serverFieldResolver resolves against the REAL ServerFields, because the point of this test is the
// direction declared on real detection settings — a synthetic field set would assert only that the
// mechanism works on fields invented to make it work.
func serverFieldResolver(db *config.DBSource) *config.Resolver {
	r := config.New(config.ServerFields, config.EnvSource{})
	r.DB = db
	return r
}

// TestAConfigChangeThatReducesDetectionPagesSomeone.
//
// Mutation: make Field.Weakens always return false, or drop the emit → no notification arrives → this
// FAILS.
func TestAConfigChangeThatReducesDetectionPagesSomeone(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	sink := &capturingSink{}
	srv.SetNotifier(sink)
	r := serverFieldResolver(config.NewDBSource())
	ctx := context.Background()

	// Tolerating six hours of silence from a host, up from the fifteen-minute default. A legitimate
	// value; no bound can refuse it; it is also how a killed agent stops being reported.
	if _, err := srv.ApplySettings(ctx, r, "operator:mallory", "quieter alerts",
		map[string]string{"OPENSHIELD_OVERDUE_THRESHOLD": "6h"}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	var found *notify.Notification
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range sink.all() {
			if n.Kind == notify.KindConfigWeakened {
				found = &n
				break
			}
		}
		if found != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if found == nil {
		t.Fatal("widening the dead-man's-switch from 15m to 6h raised NO alert. It is a valid duration " +
			"that no bound can refuse, and it is the single setting that decides whether an agent " +
			"someone killed is ever reported")
	}
	if !strings.Contains(found.Detail, "OPENSHIELD_OVERDUE_THRESHOLD") {
		t.Errorf("the alert does not name the setting: %q", found.Detail)
	}
	if !strings.Contains(found.Detail, "operator:mallory") {
		t.Errorf("the alert does not name who made the change: %q", found.Detail)
	}
}

// TestATighteningChangeIsSilent. An alert that fires on every configuration change is an alert that gets
// muted, and then the weakening one is muted with it.
//
// Mutation: emit unconditionally → this FAILS.
func TestATighteningChangeIsSilent(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	sink := &capturingSink{}
	srv.SetNotifier(sink)
	r := serverFieldResolver(config.NewDBSource())
	ctx := context.Background()

	// Noticing a silent host SOONER, and keeping evidence LONGER. Both move toward more detection.
	if _, err := srv.ApplySettings(ctx, r, "operator:alice", "tighten",
		map[string]string{
			"OPENSHIELD_OVERDUE_THRESHOLD": "5m",
			"OPENSHIELD_FLEET_RETENTION":   "4320h",
		}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	time.Sleep(2 * time.Second)
	for _, n := range sink.all() {
		if n.Kind == notify.KindConfigWeakened {
			t.Errorf("tightening detection raised a weakening alert (%q) — an alert that fires on every "+
				"change is one that gets muted, and the weakening one is muted with it", n.Detail)
		}
	}
}

// TestTheWeakeningIsOnTheDiffAnInvestigatorReads.
//
// The alert reaches whoever is on call at the time. The RECORD is what someone reconstructing "what
// changed before we stopped seeing anything" reads, months later, and it has to carry the judgement
// made at the time rather than require them to re-derive it per key.
//
// Mutation: stop writing the column, or derive it at read time → this FAILS (the second more subtly:
// re-deriving would evaluate today's declarations against an old value).
func TestTheWeakeningIsOnTheDiffAnInvestigatorReads(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	r := serverFieldResolver(config.NewDBSource())
	ctx := context.Background()

	if _, err := srv.ApplySettings(ctx, r, "operator:mallory", "",
		map[string]string{
			"OPENSHIELD_FLEET_RETENTION":   "48h", // three months of evidence becomes two days
			"OPENSHIELD_CORRELATE_WINDOW":  "30m", // narrower look-back
			"OPENSHIELD_OVERDUE_THRESHOLD": "5m",  // tightening, in the SAME revision
		}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	revs, err := srv.Revisions(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) == 0 {
		t.Fatal("no revision recorded")
	}
	byKey := map[string]bool{}
	for _, c := range revs[0].Changes {
		byKey[c.Key] = c.Weakens
	}
	for key, want := range map[string]bool{
		"OPENSHIELD_FLEET_RETENTION":   true,
		"OPENSHIELD_CORRELATE_WINDOW":  true,
		"OPENSHIELD_OVERDUE_THRESHOLD": false,
	} {
		got, ok := byKey[key]
		if !ok {
			t.Errorf("%s is not in the recorded diff", key)
			continue
		}
		if got != want {
			t.Errorf("%s recorded weakens=%v, want %v — the judgement is PER CHANGE, so a revision that "+
				"mixes a tightening with two weakenings must not be flattened either way", key, got, want)
		}
	}
}
