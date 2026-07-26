package controlplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/lucianoengel/openshield/internal/notify"
)

// The seven Tier-1 playbook steps (SOAR-4).
//
// EVERY ONE OF THESE GATHERS, RECORDS OR NOTIFIES. None blocks, kills, disables, quarantines or publishes
// a ResponseIntent — ADR-12 Tier-1, and the reason is not caution for its own sake: SOAR-7's intent seam
// gates publication on four-eyes plus a blast-radius ceiling, and SOAR-8's runners add a per-connector
// closed verb set. A playbook that could actuate would route around both. When actuation arrives it
// arrives THROUGH those gates, as a step that requests an intent, not as a step that acts.

// stepEnrich records what is known about the incident: local context, plus any THREAT-INTEL match on the
// evidence its alerts point at (SOAR-5).
//
// The threat-intel half reads observables the events already carry (never a new collection surface) and
// matches them with the SAME matcher the inline network engine blocks with. It ANNOTATES only — no alert,
// no severity change, no actuation — because a public feed is a third party's assertion and one
// over-broad entry would otherwise become fleet-wide enforcement.
//
// Still absent, and named rather than stubbed: EPSS/KEV (both key off a CVE identifier, which nothing in
// this pipeline produces) and geo/ASN (a licensed GeoIP data file).
func stepEnrich(ctx context.Context, s *Server, rc *runCtx, _ Step) (string, error) {
	var kind string
	var domains []string
	var entityID *int64
	if err := s.pool.QueryRow(ctx,
		`SELECT kind, coalesce(domains, '{}'), entity_id FROM incidents WHERE id=$1`, rc.incident.ID).
		Scan(&kind, &domains, &entityID); err != nil {
		return "", err
	}
	var contributing int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM incident_alerts WHERE incident_id=$1`, rc.incident.ID).Scan(&contributing); err != nil {
		return "", err
	}
	aliases := 0
	if entityID != nil {
		if err := s.pool.QueryRow(ctx,
			`SELECT count(*) FROM entity_aliases WHERE entity_id=$1`, *entityID).Scan(&aliases); err != nil {
			return "", err
		}
	}
	body := fmt.Sprintf(
		"local context: kind=%s severity=%s alerts=%d contributing=%d hosts=%d domains=[%s] aliases=%d window=%s→%s",
		kind, rc.incident.Severity, rc.incident.AlertCount, contributing, rc.incident.HostCount,
		strings.Join(domains, ","), aliases,
		rc.incident.FirstSeen.UTC().Format(time.RFC3339), rc.incident.LastSeen.UTC().Format(time.RFC3339))
	if err := s.addAnnotation(ctx, rc.incident.ID, "enrichment", body, rc.pb.Identity()); err != nil {
		return "", err
	}
	// SOAR-5: threat intel. A separate annotation KIND, not appended to the local-context line, so an
	// operator (and a later report) can tell a third party's assertion apart from what we observed.
	hits, err := s.EnrichIncidentWithTI(ctx, rc.incident.ID)
	if err != nil {
		return "", err
	}
	if len(hits) > 0 {
		// No annotation when there is no hit: one that says "nothing found" trains an analyst to skip
		// them, and the absence of a `ti` row already means exactly that.
		if err := s.addAnnotation(ctx, rc.incident.ID, "ti", tiAnnotationBody(hits), rc.pb.Identity()); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("annotated: %d contributing alert(s), %d domain(s), %d threat-intel hit(s)",
		contributing, len(domains), len(hits)), nil
}

// stepNotify pages through the existing fanout.
//
// The dedupe id is derived from run+step, so even a bypassed claim cannot double-page. That is defence in
// depth, and deliberately NOT what the resumption test asserts on: dedupe would mask exactly the mutation
// the test exists to catch (the D242 trap, where SIEM-12's dedupe let a duplicated projection pass).
func stepNotify(ctx context.Context, s *Server, rc *runCtx, _ Step) (string, error) {
	id := fmt.Sprintf("pb_%d_%d", rc.runID, rc.seq)
	s.emit(ctx, notify.Notification{
		Kind:      notify.KindIncident,
		Subject:   rc.incident.SubjectID,
		RiskScore: rc.incident.MaxRisk,
		At:        s.now(),
		ID:        id,
		Detail: fmt.Sprintf("playbook %s: %s incident %d — %d alerts across %d host(s)",
			rc.pb.Name, rc.incident.Severity, rc.incident.ID, rc.incident.AlertCount, rc.incident.HostCount),
	})
	return "notified " + id, nil
}

// stepOpenCase opens an investigation for the incident's subject, attributed to the playbook.
//
// It reuses OpenCaseForIncident unchanged, which also places the subject's legal hold in the same
// transaction (HON-2) — a case without its hold would leave evidence purgeable, and that invariant should
// have exactly one implementation.
func stepOpenCase(ctx context.Context, s *Server, rc *runCtx, _ Step) (string, error) {
	id, err := s.OpenCaseForIncident(ctx, Incident{
		SubjectID:  rc.incident.SubjectID,
		AlertCount: rc.incident.AlertCount,
		MaxRisk:    rc.incident.MaxRisk,
		Severity:   rc.incident.Severity,
		HostCount:  rc.incident.HostCount,
		FirstSeen:  rc.incident.FirstSeen,
		LastSeen:   rc.incident.LastSeen,
	}, rc.pb.Identity())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("case %d", id), nil
}

// stepPlaceHold holds the subject's evidence against purge WITHOUT opening a case — for the playbook that
// wants to preserve first and let a human decide whether to investigate. Idempotent by index.
func stepPlaceHold(ctx context.Context, s *Server, rc *runCtx, _ Step) (string, error) {
	if err := placeLegalHoldTx(ctx, s.pool, rc.incident.SubjectID, rc.pb.Identity(),
		fmt.Sprintf("playbook %s on incident %d", rc.pb.Name, rc.incident.ID)); err != nil {
		return "", err
	}
	return "hold placed on " + rc.incident.SubjectID, nil
}

func stepTag(ctx context.Context, s *Server, rc *runCtx, st Step) (string, error) {
	if err := s.addAnnotation(ctx, rc.incident.ID, "tag", st.Arg, rc.pb.Identity()); err != nil {
		return "", err
	}
	return "tagged " + st.Arg, nil
}

func stepAnnotate(ctx context.Context, s *Server, rc *runCtx, st Step) (string, error) {
	if err := s.addAnnotation(ctx, rc.incident.ID, "annotation", st.Arg, rc.pb.Identity()); err != nil {
		return "", err
	}
	return "annotated", nil
}

// stepWaitForApproval parks the run until a human resolves an approval (SOAR-3's first automation consumer
// — until now its only caller was case closure).
//
// HONEST SEMANTICS, because this is easy to overclaim: the requester is the PLAYBOOK, not an operator, so
// `requester <> approver` cannot mean "two humans". This is a HUMAN-IN-THE-LOOP GATE requiring exactly ONE
// operator approval. Recording an operator as the requester would be worse — it would attribute a
// machine's request to a human who never made it.
//
// The run parks rather than blocking: nothing sleeps, nothing holds a connection, and a restart mid-wait
// is indistinguishable from the next tick.
func stepWaitForApproval(ctx context.Context, s *Server, rc *runCtx, _ Step) (string, error) {
	subject := fmt.Sprintf("%d:%d", rc.runID, rc.seq)
	existing, err := s.stepApprovalID(ctx, rc.runID, rc.seq)
	if err != nil {
		return "", err
	}
	if existing == nil {
		id, err := s.RequestApproval(ctx, ApprovalSubjectPlaybookStep, subject, rc.pb.Identity(),
			fmt.Sprintf("playbook %s step %d on incident %d", rc.pb.Name, rc.seq, rc.incident.ID), 0)
		if err != nil {
			return "", err
		}
		if _, err := s.pool.Exec(ctx,
			`UPDATE playbook_steps SET approval_id=$3 WHERE run_id=$1 AND seq=$2`, rc.runID, rc.seq, id); err != nil {
			return "", err
		}
		return fmt.Sprintf("awaiting approval %d", id), errStepWaiting
	}
	// Resuming: read the decision. ApprovalFor reports a pending-past-TTL request as expired, so a dead
	// request never reads as live even before the cosmetic sweeper relabels it.
	a, err := s.ApprovalFor(ctx, ApprovalSubjectPlaybookStep, subject)
	if err != nil {
		if errors.Is(err, ErrApprovalNotFound) {
			return "", fmt.Errorf("playbook: approval %d for step %d disappeared", *existing, rc.seq)
		}
		return "", err
	}
	switch a.State {
	case ApprovalApproved:
		return fmt.Sprintf("approved by %s", a.Approver), nil
	case ApprovalPending:
		return fmt.Sprintf("awaiting approval %d", a.ID), errStepWaiting
	default:
		// Denied or expired FAILS the run. Proceeding past a refused gate would make the gate decorative;
		// what a refusal means is the requesting feature's decision, and for a playbook it means stop.
		return "", fmt.Errorf("playbook: approval %d was %s", a.ID, a.State)
	}
}

// stepApprovalID reads the approval a wait-for-approval step already opened, so a resumed run asks about
// ITS request rather than opening a second one (which the pending-per-subject index would refuse anyway).
func (s *Server) stepApprovalID(ctx context.Context, runID int64, seq int) (*int64, error) {
	var id *int64
	err := s.pool.QueryRow(ctx,
		`SELECT approval_id FROM playbook_steps WHERE run_id=$1 AND seq=$2`, runID, seq).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return id, err
}

// addAnnotation records attributed context on an incident. Separate from case_notes: a note belongs to an
// investigation a human opened; an annotation belongs to the incident and exists whether or not a case
// was ever opened.
func (s *Server) addAnnotation(ctx context.Context, incidentID int64, kind, body, author string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO incident_annotations (incident_id, kind, body, author) VALUES ($1,$2,$3,$4)`,
		incidentID, kind, truncate(body, 2048), author)
	return err
}

// IncidentAnnotation is one attributed annotation on an incident.
type IncidentAnnotation struct {
	Kind      string    `json:"kind"`
	Body      string    `json:"body"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"created_at"`
}

// IncidentAnnotations returns an incident's annotations oldest-first.
func (s *Server) IncidentAnnotations(ctx context.Context, incidentID int64) ([]IncidentAnnotation, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT kind, body, author, created_at FROM incident_annotations
		  WHERE incident_id=$1 ORDER BY created_at, id`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IncidentAnnotation
	for rows.Next() {
		var a IncidentAnnotation
		if err := rows.Scan(&a.Kind, &a.Body, &a.Author, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
