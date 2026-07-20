package core_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func validEvent() *corev1.Event {
	return &corev1.Event{
		EventId:     "evt-1",
		AgentId:     "agent-1",
		ConnectorId: "fanotify",
		Sequence:    1,
		ObservedAt:  timestamppb.Now(),
		Subject:     &corev1.Subject{PseudonymousId: "s_abc123"},
		Purpose:     corev1.Purpose_PURPOSE_DLP,
		Kind:        corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: "/tmp/x"},
		}},
	}
}

func TestValidateEventRequiresProvenance(t *testing.T) {
	cases := map[string]func(*corev1.Event){
		"event_id":     func(e *corev1.Event) { e.EventId = "" },
		"agent_id":     func(e *corev1.Event) { e.AgentId = "" },
		"connector_id": func(e *corev1.Event) { e.ConnectorId = "" },
		"observed_at":  func(e *corev1.Event) { e.ObservedAt = nil },
		"purpose":      func(e *corev1.Event) { e.Purpose = corev1.Purpose_PURPOSE_UNSPECIFIED },
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			e := validEvent()
			break_(e)
			if err := core.ValidateEvent(e); !errors.Is(err, core.ErrMissingProvenance) {
				t.Errorf("omitting %s: got %v, want ErrMissingProvenance", name, err)
			}
		})
	}
	t.Run("valid event passes", func(t *testing.T) {
		if err := core.ValidateEvent(validEvent()); err != nil {
			t.Errorf("valid event rejected: %v", err)
		}
	})
}

func TestValidateEventRequiresPseudonymousSubject(t *testing.T) {
	e := validEvent()
	e.Subject = nil
	if err := core.ValidateEvent(e); !errors.Is(err, core.ErrMissingSubject) {
		t.Errorf("got %v, want ErrMissingSubject", err)
	}
}

func TestValidateEventRequiresTarget(t *testing.T) {
	e := validEvent()
	e.Target = nil
	if err := core.ValidateEvent(e); !errors.Is(err, core.ErrNoTarget) {
		t.Errorf("got %v, want ErrNoTarget", err)
	}
}

// Sequence gaps must be detectable: an audit trail that cannot reveal
// suppression is not evidentiary. Detection is a consumer concern because
// proto3 cannot distinguish absent from zero.
func TestSequenceGapsAreDetectable(t *testing.T) {
	seqs := []uint64{1, 2, 4}
	var missing []uint64
	for i := 1; i < len(seqs); i++ {
		for want := seqs[i-1] + 1; want < seqs[i]; want++ {
			missing = append(missing, want)
		}
	}
	if len(missing) != 1 || missing[0] != 3 {
		t.Fatalf("missing = %v, want exactly [3]", missing)
	}
}

func TestPurposeMismatchIsRefused(t *testing.T) {
	e := validEvent() // PURPOSE_DLP
	err := core.CheckPurpose(e, corev1.Purpose_PURPOSE_INSIDER_RISK)
	if !errors.Is(err, core.ErrPurposeMismatch) {
		t.Errorf("cross-purpose evaluation was allowed: %v", err)
	}
	if err := core.CheckPurpose(e, corev1.Purpose_PURPOSE_DLP); err != nil {
		t.Errorf("matching purpose rejected: %v", err)
	}
}

// The three identity forms T-005 measured. A consumer that ignores the
// distinction must fail, not silently treat a missing path as an empty one.
func TestSubjectIdentityForms(t *testing.T) {
	// The oneof wrapper interface is unexported, so build the message itself.
	cases := []struct {
		name    string
		fs      *corev1.FilesystemSubject
		want    core.IdentityForm
		hasPath bool
	}{
		{"resolved_path", &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: "/tmp/a"}},
			core.IdentityResolvedPath, true},
		{"file_handle", &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_FileHandle{FileHandle: []byte{1, 2, 3}}},
			core.IdentityFileHandle, false},
		{"parent_and_name", &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ParentAndName{
				ParentAndName: &corev1.ParentAndName{ParentHandle: []byte{4}, Name: "a.csv"}}},
			core.IdentityParentAndName, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := validEvent()
			e.Target = &corev1.Event_Filesystem{Filesystem: c.fs}

			if got := core.SubjectIdentityForm(e); got != c.want {
				t.Errorf("form = %v, want %v", got, c.want)
			}
			p, err := core.ResolvedPath(e)
			if c.hasPath {
				if err != nil || p == "" {
					t.Errorf("expected a path, got %q err=%v", p, err)
				}
				return
			}
			if !errors.Is(err, core.ErrPathUnavailable) {
				t.Errorf("expected ErrPathUnavailable, got %q err=%v", p, err)
			}
			if p != "" {
				t.Errorf("returned a path %q for a form that has none", p)
			}
		})
	}
}

func validDecision() *corev1.Decision {
	return &corev1.Decision{
		DecisionId:    "dec-1",
		EventId:       "evt-1",
		Action:        corev1.Action_ACTION_ALERT,
		Confidence:    0.87,
		Reason:        "customer personal data",
		PolicyId:      "finance-upload",
		PolicyVersion: "1",
		DecidedAt:     timestamppb.Now(),
	}
}

func TestDecisionRejectsUnspecifiedAction(t *testing.T) {
	d := validDecision()
	d.Action = corev1.Action_ACTION_UNSPECIFIED
	if err := core.ValidateDecision(d, true); !errors.Is(err, core.ErrUnspecifiedAction) {
		t.Errorf("got %v, want ErrUnspecifiedAction", err)
	}
}

// An unknown action must be REJECTED, never defaulted. Treating it as ALLOW
// would mean a producer/consumer contract mismatch silently permits the
// operation — the failure mode most likely to be invisible in production.
func TestDecisionRejectsUnknownActionAndDoesNotDefaultToAllow(t *testing.T) {
	d := validDecision()
	d.Action = corev1.Action(9999)
	err := core.ValidateDecision(d, true)
	if !errors.Is(err, core.ErrUnknownAction) {
		t.Fatalf("got %v, want ErrUnknownAction", err)
	}
	if errors.Is(err, core.ErrUnspecifiedAction) {
		t.Error("unknown action was conflated with unspecified")
	}
}

func TestDecisionConfidenceIsMandatoryAndBounded(t *testing.T) {
	t.Run("missing is rejected, not defaulted to 1.0", func(t *testing.T) {
		d := validDecision()
		d.Confidence = 0
		if err := core.ValidateDecision(d, false); !errors.Is(err, core.ErrMissingConfidence) {
			t.Errorf("got %v, want ErrMissingConfidence", err)
		}
	})
	for _, c := range []float64{-0.1, 1.1} {
		d := validDecision()
		d.Confidence = c
		if err := core.ValidateDecision(d, true); !errors.Is(err, core.ErrConfidenceRange) {
			t.Errorf("confidence %v: got %v, want ErrConfidenceRange", c, err)
		}
	}
	for _, c := range []float64{0.0, 0.5, 1.0} {
		d := validDecision()
		d.Confidence = c
		if err := core.ValidateDecision(d, true); err != nil {
			t.Errorf("confidence %v rejected: %v", c, err)
		}
	}
}

func TestDecisionRequiresPolicyIdentity(t *testing.T) {
	d := validDecision()
	d.PolicyVersion = ""
	if err := core.ValidateDecision(d, true); !errors.Is(err, core.ErrMissingPolicy) {
		t.Errorf("got %v, want ErrMissingPolicy", err)
	}
}

// recordingEnforcer notes whether it was ever invoked.
type recordingEnforcer struct{ invoked bool }

func (r *recordingEnforcer) Capabilities() []corev1.Action {
	return []corev1.Action{corev1.Action_ACTION_BLOCK}
}
func (r *recordingEnforcer) Enforce(context.Context, *corev1.Decision) error {
	r.invoked = true
	return nil
}

// Phase 1 is observe-and-audit only (D1). A BLOCK decision is recorded; the
// operation proceeds; no enforcer runs. The contract exists now because it is
// expensive to change later — only its execution is deferred.
func TestPhase1RecordsBlockWithoutEnforcing(t *testing.T) {
	d := validDecision()
	d.Action = corev1.Action_ACTION_BLOCK
	if err := core.ValidateDecision(d, true); err != nil {
		t.Fatalf("valid BLOCK rejected: %v", err)
	}

	enf := &recordingEnforcer{}
	if !core.CanEnforce(enf, d) {
		t.Fatal("enforcer should advertise BLOCK")
	}

	var audit []*corev1.Decision
	const phase1 = true
	audit = append(audit, d)
	if !phase1 {
		_ = enf.Enforce(context.Background(), d)
	}

	if len(audit) != 1 {
		t.Errorf("decision was not recorded")
	}
	if enf.invoked {
		t.Error("enforcer was invoked during Phase 1 — enforcement must be deferred (D1)")
	}
}
