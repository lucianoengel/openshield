package controlplane

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// Detection domains in the unified stream (XDR-2). Coarse by design: the label groups alerts for a
// human and for a correlation rule's "distinct domains" count — it is not an authoritative taxonomy,
// and nothing downstream may treat it as one.
const (
	domainDLP  = "dlp"
	domainHIPS = "hips"
	domainNIPS = "nips"
)

// unifiedDomainFor maps an event kind to its detection domain. Total over the CLOSED EventKind enum
// (D14's discipline applied to the event contract): adding a kind without extending this mapping is
// caught by the enum-complete unit test, not discovered as a silently unprojected domain in production.
//
// Two mappings are deliberate calls rather than obvious ones:
//   - FILE_DELETED is HIPS, not DLP: it exists as the FIM tamper signal (a watched file removed), which
//     is an integrity event, not an exfiltration one.
//   - The ZT access proxy's authorization decisions arrive as HTTP_REQUEST and therefore land under
//     NIPS. Giving Zero Trust its own domain would need the Event to distinguish access from egress,
//     which it does not — a contract change is not worth a label. Revisit when XDR-4's rules show the
//     grouping loses signal.
func unifiedDomainFor(kind corev1.EventKind) (string, bool) {
	switch kind {
	case corev1.EventKind_EVENT_KIND_FILE_OPENED,
		corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		corev1.EventKind_EVENT_KIND_FILE_CREATED,
		corev1.EventKind_EVENT_KIND_USB_INSERTED:
		return domainDLP, true
	case corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
		corev1.EventKind_EVENT_KIND_FILE_DELETED,
		corev1.EventKind_EVENT_KIND_RANSOMWARE_SUSPECTED,
		corev1.EventKind_EVENT_KIND_MEMORY_INJECTION_SUSPECTED:
		return domainHIPS, true
	case corev1.EventKind_EVENT_KIND_NETWORK_FLOW,
		corev1.EventKind_EVENT_KIND_HTTP_REQUEST,
		corev1.EventKind_EVENT_KIND_DNS_QUERY,
		corev1.EventKind_EVENT_KIND_SMTP_MESSAGE:
		return domainNIPS, true
	default: // EVENT_KIND_UNSPECIFIED, or a kind added without extending this mapping
		return "", false
	}
}

// alertableAction reports whether a decision is worth an alert. An ALLOW is the pipeline working, not a
// detection — projecting it would bury every real alert under the traffic that was fine.
func alertableAction(a corev1.Action) bool {
	return a != corev1.Action_ACTION_UNSPECIFIED && a != corev1.Action_ACTION_ALLOW
}

// enforcementAction reports whether the pipeline ACTED rather than merely observed. Total over the
// closed Action set, which is exactly what makes this mapping safe: a compromised control plane cannot
// invent an action whose severity we failed to consider (D14).
func enforcementAction(a corev1.Action) bool {
	switch a {
	case corev1.Action_ACTION_BLOCK,
		corev1.Action_ACTION_QUARANTINE_LOCAL,
		corev1.Action_ACTION_ENCRYPT_LOCAL,
		corev1.Action_ACTION_REDIRECT,
		corev1.Action_ACTION_DENY_EXEC,
		corev1.Action_ACTION_KILL_PROCESS:
		return true
	default: // UNSPECIFIED, ALLOW, ALERT — observed, not enforced
		return false
	}
}

// severityForDecision buckets a decision for triage, reusing Severity() as the ONE risk→bucket mapping
// (ADR-10) rather than introducing a second scale that drifts from it. An ALERT keeps the
// confidence-derived bucket; an enforcement action takes a `high` floor, because a policy that was
// confident enough to BLOCK, DENY an exec or KILL a process has already made the impact judgement —
// a low-confidence kill is still a kill, and an analyst must see it.
func severityForDecision(a corev1.Action, confidence float64) string {
	sev := Severity(confidence)
	if enforcementAction(a) && sev != SeverityCritical {
		return SeverityHigh
	}
	return sev
}

// alertTitleFor builds the alert's human label from the CLOSED Action and EventKind enum names, and
// from nothing else.
//
// The tempting alternative — Decision.reason — is policy-authored free text that routinely quotes a
// path, a hostname or a command line, and unified_alerts is a widely-read derived table. Composing the
// title from enum names makes a content leak here unexpressible rather than merely discouraged
// (D10/D29), the same reasoning that made ClassificationSummary a separate type from LocalClassification.
func alertTitleFor(a corev1.Action, kind corev1.EventKind) string {
	return trimEnumPrefix(a.String(), "ACTION_") + " on " + trimEnumPrefix(kind.String(), "EVENT_KIND_")
}

func trimEnumPrefix(name, prefix string) string {
	return strings.ToLower(strings.TrimPrefix(name, prefix))
}

// projectDecisionAlert projects one VERIFIED decision into the entity-keyed unified alert stream
// (XDR-2), so every domain that reaches a decision — endpoint DLP/HIPS via the engine, network/DNS/SMTP
// and the ZT access proxy via the gateway — feeds the one stream XDR-4 correlates over. Before this,
// the stream had a single producer (server-side peer-UEBA) and "cross-domain correlation" had one domain.
//
// A Decision carries neither a subject nor an event kind (deliberately — an enforcer sees only the
// Decision), so the entity key and the domain come from the decision's ORIGINATING event, which the
// monotonic signed-telemetry sequence guarantees was persisted first.
//
// Derived-index discipline (D38): every failure is counted and returns; nothing here can change the
// ingest outcome, roll back the persisted telemetry, or surface an error to the producer.
func (s *Server) projectDecisionAlert(ctx context.Context, payload []byte) {
	var d corev1.Decision
	if err := proto.Unmarshal(payload, &d); err != nil {
		s.UnprojectedDecisions.Add(1)
		return
	}
	if !alertableAction(d.GetAction()) {
		return // an allowed decision is not an alert, and not a failure either
	}
	subject, kind, ok := s.originatingEvent(ctx, d.GetEventId())
	if !ok {
		// No persisted originating event: the decision cannot be keyed to an entity, and an
		// agent-keyed or unkeyed row would GROUP WRONGLY — worse than a missing one. Counted, so a
		// domain silently failing to reach correlation is visible rather than inferred from an empty
		// incident list.
		s.UnprojectedDecisions.Add(1)
		return
	}
	domain, ok := unifiedDomainFor(kind)
	if !ok {
		s.UnprojectedDecisions.Add(1)
		return
	}
	// The decision id is the natural idempotency key; fall back to (event, action) for a producer that
	// leaves it empty, so a re-delivery still dedupes instead of every such alert colliding on "".
	dedup := "decision:" + d.GetDecisionId()
	if d.GetDecisionId() == "" {
		dedup = "decision:" + d.GetEventId() + ":" + d.GetAction().String()
	}
	var at = d.GetDecidedAt().AsTime()
	if !d.GetDecidedAt().IsValid() {
		at = s.now()
	}
	// Best-effort: RecordUnifiedAlert counts its own graph/insert failures.
	_ = s.RecordUnifiedAlert(ctx, domain, xdr.KindDevice, subject,
		severityForDecision(d.GetAction(), d.GetConfidence()),
		alertTitleFor(d.GetAction(), kind), dedup, at)
}

// originatingEvent loads the VERIFIED event a decision was made about and returns the two facts the
// decision itself does not carry: the pseudonymous subject (the entity key, D23) and the event kind
// (the domain). Only verified rows qualify — unverified telemetry is not evidence (D44), so it must not
// be able to steer which entity an alert lands on.
func (s *Server) originatingEvent(ctx context.Context, eventID string) (string, corev1.EventKind, bool) {
	if eventID == "" {
		return "", corev1.EventKind_EVENT_KIND_UNSPECIFIED, false
	}
	var payload []byte
	err := s.pool.QueryRow(ctx,
		`SELECT payload FROM fleet_telemetry WHERE kind='event' AND event_id=$1 AND verified ORDER BY id LIMIT 1`,
		eventID).Scan(&payload)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.DecodeFailures.Add(1) // an infra error, distinct from a genuinely absent event
		}
		return "", corev1.EventKind_EVENT_KIND_UNSPECIFIED, false
	}
	var ev corev1.Event
	if err := proto.Unmarshal(payload, &ev); err != nil {
		return "", corev1.EventKind_EVENT_KIND_UNSPECIFIED, false
	}
	subject := ev.GetSubject().GetPseudonymousId()
	if subject == "" {
		return "", corev1.EventKind_EVENT_KIND_UNSPECIFIED, false
	}
	return subject, ev.GetKind(), true
}
