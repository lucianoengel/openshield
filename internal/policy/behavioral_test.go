package policy_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func procState(execPath, parentPath string, args ...string) *core.State {
	return &core.State{
		Event: &corev1.Event{
			EventId: "p1", Purpose: corev1.Purpose_PURPOSE_DLP,
			Kind: corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
			Target: &corev1.Event_Process{Process: &corev1.ProcessSubject{
				ExecPath: execPath, ParentPath: parentPath, Args: args}},
		},
	}
}

// HIPS-5b: the default policy ALERTs on a suspicious process-behavior score (LOLBin + suspicious
// lineage) and ALLOWs a benign exec — the built-but-unwired behavioral detection now reaches a
// decision through buildInput + the default Rego. Observe-safe: ALERT, not KILL.
func TestBehavioralAlertsOnSuspiciousProcess(t *testing.T) {
	s := mustDefault(t)

	// A web server spawning a shell: LOLBin (bash, +0.35) + suspicious lineage (nginx, +0.4) = 0.75.
	d := decide(t, s, procState("/bin/bash", "/usr/sbin/nginx", "bash", "-c", "id"))
	if d.GetAction() != corev1.Action_ACTION_ALERT {
		t.Errorf("suspicious process action = %v, want ALERT (behavioral detection did not reach the decision)", d.GetAction())
	}

	// A benign exec: ls is not a LOLBin and bash is not a suspicious parent → score 0 → ALLOW.
	b := decide(t, s, procState("/bin/ls", "/bin/bash", "ls", "-l"))
	if b.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Errorf("benign process action = %v, want ALLOW", b.GetAction())
	}
}

// A file event carries no behavioral signal — the behavioral rule must not fire on it (no
// input.event.behavioral), so a clean file event still ALLOWs.
func TestBehavioralDoesNotFireOnFileEvents(t *testing.T) {
	s := mustDefault(t)
	d := decide(t, s, &core.State{
		Event: &corev1.Event{EventId: "f1", Purpose: corev1.Purpose_PURPOSE_DLP,
			Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED},
		Classification: &corev1.LocalClassification{EventId: "f1"},
	})
	if d.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Errorf("clean file event action = %v, want ALLOW", d.GetAction())
	}
}
