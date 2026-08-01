package policy_test

import (
	"context"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// DSPM-2: an object discovered at rest reaches Rego, and its bucket's EXPOSURE is what ranks the finding.
//
// This is the D313 defect again. ObjectSubject shipped with the discovery sweep and `GetObject` had exactly
// one caller in the tree — a test — so bucket, key and store never reached the policy at all. sweep.go's own
// doc comment justified the structured subject by saying it spares "every policy that wants
// `bucket = finance-exports`" from parsing a string, and that rule could not be written.
//
// The module below is what an operator would actually write: sensitive content is a fact, sensitive content
// in a world-readable bucket is an incident, and only the policy layer holds that opinion.
const objectExposureModule = `package openshield
import rego.v1

default decision := {"action": "ALLOW", "reason": "no rule matched"}

decision := {"action": "ALERT", "reason": "sensitive data in a world-readable bucket"} if {
	input.event.object.exposure == "OBJECT_EXPOSURE_PUBLIC"
	some h in input.classification
	h.type == "DETECTOR_TYPE_CPF"
}

decision := {"action": "ALERT", "reason": "the exposure of this bucket could not be established"} if {
	input.event.object.exposure == "OBJECT_EXPOSURE_UNSPECIFIED"
	some h in input.classification
	h.type == "DETECTOR_TYPE_CPF"
}

decision := {"action": "ALERT", "reason": "finance exports"} if {
	input.event.object.bucket == "finance-exports"
	not input.event.object.access_complete
}
`

func objectState(bucket string, access *corev1.ObjectAccess) *core.State {
	return &core.State{
		Event: &corev1.Event{
			EventId: "o1", Purpose: corev1.Purpose_PURPOSE_DLP,
			Kind: corev1.EventKind_EVENT_KIND_OBJECT_DISCOVERED,
			Target: &corev1.Event_Object{Object: &corev1.ObjectSubject{
				Store: "minio.internal", Bucket: bucket, Key: "customers.csv",
				SizeBytes: 4096, BytesExamined: 4096, Access: access,
			}},
		},
		Classification: &corev1.LocalClassification{
			EventId: "o1", Matches: []*corev1.LocalMatch{cpfMatch(0.9)},
		},
	}
}

func objectStage(t *testing.T) *policy.Stage {
	t.Helper()
	s, err := policy.New(context.Background(), "dspm2", "v1", objectExposureModule)
	if err != nil {
		t.Fatalf("loading the exposure policy: %v", err)
	}
	return s
}

func TestBucketExposureRanksADiscoveryFinding(t *testing.T) {
	s := objectStage(t)

	public := decide(t, s, objectState("customer-data", &corev1.ObjectAccess{
		Exposure: corev1.ObjectExposure_OBJECT_EXPOSURE_PUBLIC,
	}))
	if public.GetAction() != corev1.Action_ACTION_ALERT {
		t.Errorf("public bucket action = %v, want ALERT", public.GetAction())
	}

	// THE NEGATIVE IS THE HALF THAT MAKES THE POSITIVE MEAN ANYTHING. The same object, the same
	// classification, the same detector confidence — only the bucket's exposure differs. Without this, a
	// stage that alerted on every discovered object would pass the assertion above.
	private := decide(t, s, objectState("customer-data", &corev1.ObjectAccess{
		Exposure: corev1.ObjectExposure_OBJECT_EXPOSURE_PRIVATE,
	}))
	if private.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Errorf("private bucket action = %v, want ALLOW — the exposure is not being read", private.GetAction())
	}
}

// An access context nobody could establish must be distinguishable in Rego from one that came back private.
// It reaches the policy as UNSPECIFIED, so a rule can treat not-knowing as its own finding — and, because
// UNSPECIFIED is the proto default, a policy that only tests for PUBLIC gets no false reassurance from a
// field that was never set.
func TestAnUnknownExposureIsNotSilentlyPrivate(t *testing.T) {
	s := objectStage(t)
	d := decide(t, s, objectState("customer-data", &corev1.ObjectAccess{
		Exposure:  corev1.ObjectExposure_OBJECT_EXPOSURE_UNSPECIFIED,
		Unchecked: []string{"bucket ACL (this credential is not permitted to read it)"},
	}))
	if d.GetAction() != corev1.Action_ACTION_ALERT {
		t.Fatalf("unknown exposure action = %v, want ALERT", d.GetAction())
	}
	if d.GetReason() != "the exposure of this bucket could not be established" {
		t.Fatalf("reason = %q, want the unknown-exposure reason", d.GetReason())
	}
}

// The bucket identity itself — the rule sweep.go said the structured subject existed to make writable.
func TestBucketIdentityAndCompletenessReachThePolicy(t *testing.T) {
	s := objectStage(t)
	d := decide(t, s, objectState("finance-exports", &corev1.ObjectAccess{
		Exposure:  corev1.ObjectExposure_OBJECT_EXPOSURE_PRIVATE,
		Unchecked: []string{"bucket policy (this credential is not permitted to read it)"},
	}))
	if d.GetReason() != "finance exports" {
		t.Fatalf("reason = %q, want the bucket-name rule to have matched", d.GetReason())
	}

	// access_complete is derived, not carried: an empty Unchecked means the picture is whole, and the rule
	// above must then NOT fire.
	whole := decide(t, s, objectState("finance-exports", &corev1.ObjectAccess{
		Exposure: corev1.ObjectExposure_OBJECT_EXPOSURE_PRIVATE,
	}))
	if whole.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("a complete access picture still matched the incomplete rule: %v", whole.GetAction())
	}
}

// A discovery event is NOT an exfiltration. Nothing moved; somebody looked. Tagging it with a channel would
// have been the tidy-looking move and would have widened every already-written "nothing sensitive to cloud
// sync" rule to fire on data that has been sitting still for two years — changing what an operator's policy
// means without them touching it.
func TestDiscoveryIsNotTaggedAsAnExfilChannel(t *testing.T) {
	s, err := policy.New(context.Background(), "chan", "v1", `package openshield
import rego.v1
default decision := {"action": "ALLOW", "reason": "no channel"}
decision := {"action": "BLOCK", "reason": "channelled"} if { input.event.exfil_channel }`)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	d := decide(t, s, objectState("customer-data", &corev1.ObjectAccess{
		Exposure: corev1.ObjectExposure_OBJECT_EXPOSURE_PUBLIC,
	}))
	if d.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("a discovered object carries an exfil_channel: %v — data at rest did not move anywhere", d.GetAction())
	}
}
