package engine_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
)

// countingClassifier records every event whose CONTENT the pipeline tried to classify. The whole
// privacy claim is that this never happens for an excluded subject — "the honest way not to surveil
// something is not to look at it" — so counting classification, rather than counting decisions, is
// what makes the assertion mean what the requirement says.
type countingClassifier struct {
	seen []string
}

func (c *countingClassifier) Classify(_ context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	c.seen = append(c.seen, req.GetEventId())
	return &corev1.ClassifyResponse{RequestId: req.GetRequestId(), EventId: req.GetEventId()}, nil
}

func fileEventAt(id, path string, at time.Time) *corev1.Event {
	return &corev1.Event{
		EventId:     id,
		AgentId:     "a",
		ConnectorId: "fanotify",
		Kind:        corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		Purpose:     corev1.Purpose_PURPOSE_DLP,
		ObservedAt:  timestamppb.New(at),
		Subject:     &corev1.Subject{PseudonymousId: "sub"},
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: path}}},
	}
}

// pathlessEventAt carries the FILE-HANDLE subject identity, which resolves to no path at all — two of
// the three fanotify identity forms are like this (docs/spike-t005-fanotify.md).
func pathlessEventAt(id string, at time.Time) *corev1.Event {
	return &corev1.Event{
		EventId:     id,
		AgentId:     "a",
		ConnectorId: "fanotify",
		Kind:        corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		Purpose:     corev1.Purpose_PURPOSE_DLP,
		ObservedAt:  timestamppb.New(at),
		Subject:     &corev1.Subject{PseudonymousId: "sub"},
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_FileHandle{FileHandle: []byte{1, 2, 3}}}},
	}
}

func excludingEngine(t *testing.T, set core.ExclusionSet) (*engine.Engine, *countingClassifier) {
	t.Helper()
	cls := &countingClassifier{}
	eng := engine.New(cls, alertingPolicy(), &recLedger{}, nil, 5*time.Second)
	eng.SetExclusions(set)
	return eng, cls
}

// TestAnExcludedSubjectIsNeverClassified is the PRIV-1 acceptance test, and it asserts the thing the
// requirement actually claims: not that the event was dropped somewhere downstream, but that
// CLASSIFICATION NEVER RAN — so the bytes were never read and no personal data was created.
//
// Before this, core.ExclusionSet had no caller anywhere in the shipped tree. The predicate was
// correct and inert, and the DPIA template asked deployers to record exclusions they had no way to
// configure.
//
// Mutation: drop the isExcluded check from ProcessObserved → the excluded paths appear in the
// classifier's list → this FAILS.
func TestAnExcludedSubjectIsNeverClassified(t *testing.T) {
	noon := time.Date(2026, 8, 3, 12, 30, 0, 0, time.Local)
	morning := time.Date(2026, 8, 3, 9, 15, 0, 0, time.Local)

	t.Run("a personal folder is not observed", func(t *testing.T) {
		eng, cls := excludingEngine(t, core.ExclusionSet{PathPrefixes: []string{"/home/u/Private"}})
		for _, tc := range []struct{ id, path string }{
			{"excluded", "/home/u/Private/diary.txt"},
			{"observed", "/home/u/work/report.txt"},
		} {
			if _, err := eng.ProcessObserved(context.Background(), fileEventAt(tc.id, tc.path, morning)); err != nil {
				t.Fatalf("%s: %v", tc.id, err)
			}
		}
		assertClassified(t, cls, "observed")
		if eng.Excluded() != 1 {
			t.Errorf("Excluded() = %d, want 1", eng.Excluded())
		}
		if eng.ExclusionsUnevaluable() != 0 {
			t.Errorf("ExclusionsUnevaluable() = %d, want 0 — both events carried a resolved path",
				eng.ExclusionsUnevaluable())
		}
	})

	t.Run("a break-time window is not observed", func(t *testing.T) {
		eng, cls := excludingEngine(t, core.ExclusionSet{
			TimeWindows: []core.TimeWindow{{StartMin: 12 * 60, EndMin: 13 * 60}}})
		if _, err := eng.ProcessObserved(context.Background(),
			fileEventAt("lunch", "/home/u/work/report.txt", noon)); err != nil {
			t.Fatal(err)
		}
		if _, err := eng.ProcessObserved(context.Background(),
			fileEventAt("morning", "/home/u/work/report.txt", morning)); err != nil {
			t.Fatal(err)
		}
		assertClassified(t, cls, "morning")
	})

	t.Run("a time window applies to a subject carrying no path", func(t *testing.T) {
		// The two halves are asymmetric and it matters: a window needs only the timestamp, so the
		// break-time control is COMPLETE regardless of coverage mode, while the personal-folder
		// control is conditional on it.
		eng, cls := excludingEngine(t, core.ExclusionSet{
			TimeWindows: []core.TimeWindow{{StartMin: 12 * 60, EndMin: 13 * 60}}})
		// It is EXCLUDED, so the classify stage's refusal of a path-less file event is never even
		// reached — a nil error here proves the event was suppressed rather than merely failing.
		dec, err := eng.ProcessObserved(context.Background(), pathlessEventAt("lunch-nopath", noon))
		if err != nil || dec != nil {
			t.Fatalf("ProcessObserved = %v, %v; want (nil, nil) — a break-time window needs only the "+
				"timestamp, so it must apply whatever subject identity the event carries", dec, err)
		}
		assertClassified(t /* nothing */, cls)
		if eng.ExclusionsUnevaluable() != 0 {
			t.Errorf("ExclusionsUnevaluable() = %d, want 0 — a time window is always evaluable, so "+
				"counting this as a gap would overstate the hole in the privacy claim",
				eng.ExclusionsUnevaluable())
		}
	})
}

// A PATH exclusion cannot be evaluated against a subject identity that carries no path. The event is
// OBSERVED — the safe direction for detection — and the fact is COUNTED, because the alternative is an
// operator telling a works council that personal folders are unobserved while some of them are read.
//
// Mutation: return true (exclude) instead of counting → the event is not classified → this FAILS.
// Mutation: drop the counter increment → the number stays 0 → this FAILS.
func TestAPathExclusionThatCannotBeEvaluatedIsCountedNotGuessed(t *testing.T) {
	morning := time.Date(2026, 8, 3, 9, 15, 0, 0, time.Local)
	eng, cls := excludingEngine(t, core.ExclusionSet{PathPrefixes: []string{"/home/u/Private"}})

	// The pipeline REFUSES a file event with no resolvable path (the classify stage errors rather than
	// reporting a clean result). That is pre-existing and correct, and it bounds the exposure: what
	// escapes the exclusion here is the event's metadata, never the file's bytes. The point of this
	// test is that the engine did not silently decide the question either way.
	if _, err := eng.ProcessObserved(context.Background(), pathlessEventAt("nopath", morning)); err == nil {
		t.Fatal("a file event with no resolvable path was classified — the exclusion cannot be " +
			"evaluated for it, and treating it as clean would be a silent clean result (D17)")
	}
	assertClassified(t, cls) // never reached the worker
	if eng.Excluded() != 0 {
		t.Errorf("Excluded() = %d, want 0 — an unevaluable exclusion must not be reported as applied",
			eng.Excluded())
	}
	if eng.ExclusionsUnevaluable() != 1 {
		t.Fatalf("ExclusionsUnevaluable() = %d, want 1 — an operator reading this number is reading "+
			"the exact size of the hole in the privacy claim they made; zero would state there is none",
			eng.ExclusionsUnevaluable())
	}

	// AN EVENT THAT IS NOT ABOUT A FILE IS NOT A GAP. A DNS query, a USB insert or an exec carries no
	// path because it is not about a file, and a personal-folder exclusion was never going to apply.
	// Counting those would bury the real number under traffic that was never in scope, and the
	// counter would report a hole far larger than the one that exists.
	if _, err := eng.ProcessObserved(context.Background(), &corev1.Event{
		EventId: "dns", AgentId: "a", ConnectorId: "dns",
		Kind: corev1.EventKind_EVENT_KIND_DNS_QUERY, ObservedAt: timestamppb.New(morning),
		Subject: &corev1.Subject{PseudonymousId: "sub"},
		Target: &corev1.Event_Network{Network: &corev1.NetworkSubject{
			SniHost: "example.com"}},
	}); err != nil {
		t.Fatalf("dns: %v", err)
	}
	if eng.ExclusionsUnevaluable() != 1 {
		t.Errorf("ExclusionsUnevaluable() = %d after a DNS query, want still 1 — a non-file event is "+
			"not a gap in a personal-folder exclusion", eng.ExclusionsUnevaluable())
	}

	// With NO path exclusion configured there is no claim to hole, so nothing is counted.
	eng2, _ := excludingEngine(t, core.ExclusionSet{
		TimeWindows: []core.TimeWindow{{StartMin: 1, EndMin: 2}}})
	_, _ = eng2.ProcessObserved(context.Background(), pathlessEventAt("nopath2", morning))
	if eng2.ExclusionsUnevaluable() != 0 {
		t.Errorf("ExclusionsUnevaluable() = %d with no path exclusion configured, want 0",
			eng2.ExclusionsUnevaluable())
	}
}

// THE SECURITY BOUNDARY. Process is the entry for producers that need a VERDICT they will act on —
// the exec gate, the clipboard mediator, the print and mail deciders — where a suppressed decision
// necessarily resolves to allow. An exclusion there would turn a break-time window into a nightly
// interval in which any binary runs, reachable by any user willing to wait until 12:00.
//
// The requirement this implements says an exclusion is "a privacy control, not a user-invokable DLP
// evasion". Excluding a verdict is that evasion.
//
// Mutation: apply the exclusion in Process rather than in ProcessObserved → the verdict path is
// suppressed → this FAILS.
func TestAnExclusionNeverSuppressesAVerdict(t *testing.T) {
	noon := time.Date(2026, 8, 3, 12, 30, 0, 0, time.Local)
	eng, cls := excludingEngine(t, core.ExclusionSet{
		PathPrefixes: []string{"/home/u/Private"},
		TimeWindows:  []core.TimeWindow{{StartMin: 12 * 60, EndMin: 13 * 60}},
	})

	// Both halves of the exclusion match this event, and it is still decided — because the caller
	// asked for a verdict.
	dec, err := eng.Process(context.Background(), fileEventAt("gate", "/home/u/Private/x.sh", noon))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if dec == nil {
		t.Fatal("Process returned no decision for an excluded subject — a verdict path that returns " +
			"nothing resolves to ALLOW, which makes the exclusion a user-invokable DLP evasion")
	}
	assertClassified(t, cls, "gate")
	if eng.Excluded() != 0 {
		t.Errorf("Excluded() = %d, want 0 — a verdict is never counted as an exclusion", eng.Excluded())
	}
}

// alertingPolicy always produces a well-formed ALERT, so "was there a decision?" is a clean signal:
// nil means the pipeline was suppressed, not that the policy happened to say nothing.
func alertingPolicy() core.Stage {
	return stageFunc("policy", func(_ context.Context, st *core.State) (core.Outcome, error) {
		return core.Decided(&corev1.Decision{
			DecisionId: "d-" + st.Event.GetEventId(), EventId: st.Event.GetEventId(),
			Action: corev1.Action_ACTION_ALERT, Confidence: 0.5,
			PolicyId: "test", PolicyVersion: "1",
		}), nil
	})
}

func assertClassified(t *testing.T, c *countingClassifier, want ...string) {
	t.Helper()
	if len(c.seen) != len(want) {
		t.Fatalf("classified %v, want %v — an excluded subject's bytes must never be read", c.seen, want)
	}
	for i := range want {
		if c.seen[i] != want[i] {
			t.Fatalf("classified %v, want %v", c.seen, want)
		}
	}
}
