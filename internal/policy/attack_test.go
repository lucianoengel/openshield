package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// A policy can route on a MITRE ATT&CK technique (SIEM-7): input.attack.techniques
// carries the techniques the state's signals evidence, so a rule can block a
// cloud-storage exfiltration (T1567.002) of a credential (T1552).
func TestAttackTechniqueAwarePolicy(t *testing.T) {
	mod := `package openshield
import rego.v1

has_technique(id) if { some t in input.attack.techniques; t == id }

decision := {"action":"BLOCK","reason":"credential exfil to cloud","confidence":0.95} if {
	has_technique("T1567.002")
	has_technique("T1552")
}
decision := {"action":"ALERT","reason":"other","confidence":0.5} if {
	not has_technique("T1567.002")
}`
	pol, err := policy.New(context.Background(), "siem7", "1", mod)
	if err != nil {
		t.Fatal(err)
	}

	// A credential written to a cloud-sync folder → T1552 + T1567.002 → BLOCK.
	var reg core.Registry
	reg.Register(classifyStage{hits: []*corev1.LocalMatch{
		{DetectorType: corev1.DetectorType_DETECTOR_TYPE_AWS_ACCESS_KEY, Confidence: 0.9},
	}})
	reg.Register(pol)
	disp := core.NewDispatcher(&reg, time.Second)
	ev := &corev1.Event{
		EventId: "e", Purpose: corev1.Purpose_PURPOSE_DLP,
		Kind:    corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		Subject: &corev1.Subject{PseudonymousId: "sub_u"},
		Target:  &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: "/home/u/Dropbox/keys.txt"}}},
	}
	dec, err := disp.Dispatch(context.Background(), ev)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Fatalf("credential to cloud-sync = %v, want BLOCK (T1567.002 + T1552)", dec.GetAction())
	}
}

// XDR-4b: the Decision now CARRIES the technique ids, so correlation can hunt by technique rather
// than by the coarse domain label. Two properties, and the second is the load-bearing one.
func TestTheDecisionCarriesTheDerivedTechniquesAndOnlyThose(t *testing.T) {
	dispatchWith := func(t *testing.T, mod string, ev *corev1.Event, hits []*corev1.LocalMatch) *corev1.Decision {
		t.Helper()
		pol, err := policy.New(context.Background(), "xdr4b", "1", mod)
		if err != nil {
			t.Fatal(err)
		}
		var reg core.Registry
		reg.Register(classifyStage{hits: hits})
		reg.Register(pol)
		dec, err := core.NewDispatcher(&reg, time.Second).Dispatch(context.Background(), ev)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		return dec
	}
	credentialToCloud := func() *corev1.Event {
		return &corev1.Event{
			EventId: "e", Purpose: corev1.Purpose_PURPOSE_DLP,
			Kind:    corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
			Subject: &corev1.Subject{PseudonymousId: "sub_u"},
			Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
				Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: "/home/u/Dropbox/keys.txt"}}},
		}
	}
	credHit := []*corev1.LocalMatch{
		{DetectorType: corev1.DetectorType_DETECTOR_TYPE_AWS_ACCESS_KEY, Confidence: 0.9},
	}
	alertAlways := `package openshield
import rego.v1
decision := {"action":"ALERT","reason":"r","confidence":0.5}`

	t.Run("the derivation reaches the Decision", func(t *testing.T) {
		dec := dispatchWith(t, alertAlways, credentialToCloud(), credHit)
		want := map[string]bool{"T1552": true, "T1567.002": true}
		got := map[string]bool{}
		for _, id := range dec.GetTechniques() {
			got[id] = true
		}
		if len(got) != len(want) {
			t.Fatalf("Techniques = %v, want %v", dec.GetTechniques(), []string{"T1552", "T1567.002"})
		}
		for id := range want {
			if !got[id] {
				t.Fatalf("Techniques = %v, missing %s", dec.GetTechniques(), id)
			}
		}
		// And every id it carries satisfies the contract — otherwise the projection would refuse the
		// decision and the alert would never reach the stream.
		if err := core.ValidateDecision(dec, true); err != nil {
			t.Fatalf("the evaluator produced a decision its own contract refuses: %v", err)
		}
	})

	// THE LOAD-BEARING PROPERTY. A policy module is operator-authored text composed from a default
	// pack, compliance packs and a custom module. If a rule could DECLARE a technique, then "what did
	// this asset evidence?" would be answered by whatever the rules asserted — and the
	// technique-sequence hunt would correlate claims rather than signals. Policy decides what to DO
	// about signals; it never decides what the signals WERE.
	t.Run("a policy that declares a technique does not put it on the Decision", func(t *testing.T) {
		liar := `package openshield
import rego.v1
decision := {"action":"ALERT","reason":"r","confidence":0.5,
             "techniques":["T1486","T1071","T1052"],
             "attack":{"techniques":["T1486"]}}`
		// A benign event with NO mappable signal: whatever techniques come back can only have come
		// from the policy text.
		benign := &corev1.Event{
			EventId: "e2", Purpose: corev1.Purpose_PURPOSE_DLP,
			Kind:    corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
			Subject: &corev1.Subject{PseudonymousId: "sub_u"},
			Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
				Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: "/home/u/notes.txt"}}},
		}
		dec := dispatchWith(t, liar, benign, nil)
		if len(dec.GetTechniques()) != 0 {
			t.Fatalf("a policy DECLARED techniques and they reached the Decision: %v — the "+
				"technique must be derived from signals, never read out of a policy result",
				dec.GetTechniques())
		}
	})
}
