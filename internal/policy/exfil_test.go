package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// A DLP policy can escalate on the EXFIL CHANNEL (DLP-2): the same sensitive
// classification blocks when the file is written to a cloud-sync/removable channel
// but only alerts locally. The channel is exposed at input.event.exfil_channel,
// derived content-free from the path, and drives the decision through the UNCHANGED
// dispatcher.
func TestExfilChannelAwarePolicy(t *testing.T) {
	mod := `package openshield
import rego.v1

sensitive if { some m in input.classification; m.count > 0 }
exfil if { input.event.exfil_channel == "cloud_sync" }
exfil if { input.event.exfil_channel == "removable" }

# Sensitive content heading to an exfil channel → BLOCK.
decision := {"action":"BLOCK","reason":"sensitive data to an exfil channel","confidence":0.9} if {
	sensitive
	exfil
}
# Sensitive content staying local → ALERT only.
decision := {"action":"ALERT","reason":"sensitive local write","confidence":0.6} if {
	sensitive
	not exfil
}
# Nothing sensitive → ALLOW.
decision := {"action":"ALLOW","reason":"clean","confidence":0.9} if { not sensitive }`
	pol, err := policy.New(context.Background(), "dlp2", "1", mod)
	if err != nil {
		t.Fatal(err)
	}

	decide := func(t *testing.T, path string, sensitive bool) corev1.Action {
		t.Helper()
		var hits []*corev1.LocalMatch
		if sensitive {
			hits = []*corev1.LocalMatch{{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD, Confidence: 0.95}}
		}
		var reg core.Registry
		reg.Register(classifyStage{hits: hits})
		reg.Register(pol)
		disp := core.NewDispatcher(&reg, time.Second)
		ev := &corev1.Event{
			EventId: "e", Purpose: corev1.Purpose_PURPOSE_DLP,
			Kind:    corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
			Subject: &corev1.Subject{PseudonymousId: "sub_u"},
			Target:  &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: path}}},
		}
		dec, err := disp.Dispatch(context.Background(), ev)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		return dec.GetAction()
	}

	// Sensitive write to a cloud-sync folder → BLOCK.
	if got := decide(t, "/home/u/Dropbox/customers.xlsx", true); got != corev1.Action_ACTION_BLOCK {
		t.Fatalf("sensitive cloud-sync write = %v, want BLOCK", got)
	}
	// Sensitive write to removable media → BLOCK.
	if got := decide(t, "/media/usb0/customers.xlsx", true); got != corev1.Action_ACTION_BLOCK {
		t.Fatalf("sensitive removable write = %v, want BLOCK", got)
	}
	// Same sensitive content, local → ALERT only.
	if got := decide(t, "/home/u/docs/customers.xlsx", true); got != corev1.Action_ACTION_ALERT {
		t.Fatalf("sensitive local write = %v, want ALERT", got)
	}
	// Clean content to a cloud folder → ALLOW (channel alone is not a leak).
	if got := decide(t, "/home/u/Dropbox/cat.jpg", false); got != corev1.Action_ACTION_ALLOW {
		t.Fatalf("clean cloud-sync write = %v, want ALLOW", got)
	}
}

