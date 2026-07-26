package controlplane_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/notify"
)

// SOAR-9's control-plane half: the severity stamp, and telling a human that an approval is pending.

// TestSeverityVocabularyDoesNotDrift — the routing package ranks severity labels; the risk→label MAPPING
// stays in the control plane (SIEM-6) and is deliberately NOT duplicated there. This is what keeps the two
// from silently diverging: every control-plane severity constant must rank in notify.
func TestSeverityVocabularyDoesNotDrift(t *testing.T) {
	for _, s := range []string{
		controlplane.SeverityLow, controlplane.SeverityMedium,
		controlplane.SeverityHigh, controlplane.SeverityCritical,
	} {
		if _, ok := notify.SeverityRank(s); !ok {
			t.Errorf("control-plane severity %q does not rank in notify — the routing vocabulary and the "+
				"risk→bucket mapping have drifted, so a rule with that floor silently matches nothing", s)
		}
	}
	// And the mapping itself still produces only rankable labels.
	for _, risk := range []float64{0.0, 0.4, 0.5, 0.74, 0.75, 0.89, 0.9, 1.0} {
		if _, ok := notify.SeverityRank(controlplane.Severity(risk)); !ok {
			t.Errorf("Severity(%v) = %q, which does not rank", risk, controlplane.Severity(risk))
		}
	}
}

// TestEmitStampsRoutingSeverity: the stamp happens in the single funnel every notification passes
// through, so routing has something to match on without notify learning the risk→bucket mapping.
func TestEmitStampsRoutingSeverity(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	sink := &capturingSink{}
	srv.SetNotifier(sink)

	srv.EmitForTest(notify.Notification{Kind: notify.KindPeerAlert, Subject: "s1", RiskScore: 0.95, ID: "n-crit"})
	srv.EmitForTest(notify.Notification{Kind: notify.KindPeerAlert, Subject: "s2", RiskScore: 0.30, ID: "n-low"})
	// A producer that already set a severity is left alone.
	srv.EmitForTest(notify.Notification{Kind: notify.KindIncident, Subject: "s3", RiskScore: 0.95,
		Severity: controlplane.SeverityMedium, ID: "n-explicit"})

	waitFor(t, func() bool { return sink.count() >= 3 })
	got := sink.byID()
	if got["n-crit"] != controlplane.SeverityCritical {
		t.Errorf("risk 0.95 stamped %q, want critical", got["n-crit"])
	}
	if got["n-low"] != controlplane.SeverityLow {
		t.Errorf("risk 0.30 stamped %q, want low", got["n-low"])
	}
	if got["n-explicit"] != controlplane.SeverityMedium {
		t.Errorf("an explicitly-set severity was overwritten with %q — the producer knows better than the "+
			"risk score for a derived notification", got["n-explicit"])
	}
}

// TestRequestingAnApprovalNotifies closes SOAR-3's named residual ("it notifies nobody that an approval is
// pending") and is what makes SOAR-4's wait-for-approval step usable rather than a deadlock: before this,
// a parked playbook run waited on a human who was never told the approval existed.
//
// Mutation: do not emit on RequestApproval → FAILS.
func TestRequestingAnApprovalNotifies(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	sink := &capturingSink{}
	srv.SetNotifier(sink)
	ctx := context.Background()

	id, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectPlaybookStep, "42:1",
		"playbook:gated-response", "a reason the requester typed", 0)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return sink.count() >= 1 })
	n := sink.first()
	if n.Kind != notify.KindApprovalPending {
		t.Errorf("kind = %q, want %q", n.Kind, notify.KindApprovalPending)
	}
	if n.Subject != "42:1" {
		t.Errorf("subject = %q, want the approval's subject so a recipient can find it", n.Subject)
	}
	if !strings.Contains(n.Detail, controlplane.ApprovalSubjectPlaybookStep) {
		t.Errorf("detail %q does not name the subject kind", n.Detail)
	}
	if _, ok := notify.SeverityRank(n.Severity); !ok {
		t.Errorf("the approval notification carries severity %q, which does not rank — it would fall to "+
			"the unrouted fail-open on every delivery", n.Severity)
	}

	// The requester's free-text REASON must not become a routing input: routing decides on a closed
	// vocabulary, and matching on free text would make the decision depend on what a requester typed.
	if n.Severity == "a reason the requester typed" || n.Kind == notify.Kind("a reason the requester typed") {
		t.Error("the reason text reached a routing field")
	}

	// The approvals ROW is the record; delivery is additive. It exists regardless.
	a, err := srv.ApprovalFor(ctx, controlplane.ApprovalSubjectPlaybookStep, "42:1")
	if err != nil || a.ID != id {
		t.Fatalf("the approval was not recorded: %+v err=%v", a, err)
	}
}

// TestApprovalIsRecordedEvenWhenDeliveryFails — the database row is the record.
func TestApprovalIsRecordedEvenWhenDeliveryFails(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	srv.SetNotifier(&failingSink{})
	ctx := context.Background()

	id, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-1",
		"operator:alice", "contain a host", 0)
	if err != nil {
		t.Fatalf("a failing sink failed the approval request: %v — the row is the record, delivery is an "+
			"additive copy", err)
	}
	a, err := srv.ApprovalFor(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-1")
	if err != nil || a.ID != id || a.State != controlplane.ApprovalPending {
		t.Fatalf("approval not pending after a delivery failure: %+v err=%v", a, err)
	}
}

// capturingSink keeps the delivered notifications so their routing fields can be inspected.
type capturingSink struct {
	mu  sync.Mutex
	got []notify.Notification
}

func (c *capturingSink) Notify(_ context.Context, n notify.Notification) error {
	c.mu.Lock()
	c.got = append(c.got, n)
	c.mu.Unlock()
	return nil
}

func (c *capturingSink) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func (c *capturingSink) first() notify.Notification {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.got) == 0 {
		return notify.Notification{}
	}
	return c.got[0]
}

func (c *capturingSink) byID() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]string{}
	for _, n := range c.got {
		out[n.ID] = n.Severity
	}
	return out
}

// failingSink proves delivery is additive: the approvals row must exist regardless.
type failingSink struct{}

func (failingSink) Notify(context.Context, notify.Notification) error {
	return errors.New("sink unavailable")
}
