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
