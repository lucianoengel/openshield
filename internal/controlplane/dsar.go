package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// DSAR — data-subject access request (PLAT-8). A privacy regime (GDPR Art. 15, LGPD Art. 18)
// gives a person the right to know what a system holds about them. OpenShield holds only
// PSEUDONYMOUS records (D23), so a DSAR is compiled by pseudonymous subject id: it gathers, from
// every subject-keyed store, a summary of what is held — the audit entries, the peer-UEBA
// alerts, the investigation cases, and whether the subject is under a legal hold that would
// override erasure.
//
// It is an ACCESS report (what is held), not the raw content: the ledger's content is already
// erasable under retention (D-privacy) and never leaves pseudonymous, and the point of a DSAR is
// the inventory. Running a DSAR is itself a privacy-sensitive act, so — like viewing an
// investigation (D56) — it is RECORDED against the operator's identity before the report is
// returned: an access that left no trace of who ran it would be the opposite of accountable.

// SubjectReport is the compiled answer to "what does the platform hold about this subject?"
type SubjectReport struct {
	SubjectID      string    `json:"subject_id"`
	AuditEntries   SpanCount `json:"audit_entries"`
	PeerAlerts     AlertSpan `json:"peer_alerts"`
	Cases          []Case    `json:"cases"`
	UnderLegalHold bool      `json:"under_legal_hold"`
	GeneratedAt    time.Time `json:"generated_at"`
}

// SpanCount is a count of records and the time span they cover (nil bounds when count is 0).
type SpanCount struct {
	Count   int        `json:"count"`
	FirstAt *time.Time `json:"first_at,omitempty"`
	LastAt  *time.Time `json:"last_at,omitempty"`
}

// AlertSpan is a SpanCount plus the peak risk / severity across the subject's alerts.
type AlertSpan struct {
	SpanCount
	MaxRisk     float64 `json:"max_risk"`
	MaxSeverity string  `json:"max_severity"`
}

// SubjectAccessReport compiles the DSAR report for a pseudonymous subject. It reads each
// subject-keyed store; an empty subject id is refused (a DSAR over "everyone" is not a
// data-subject request and would dump the whole store).
func (s *Server) SubjectAccessReport(ctx context.Context, subjectID string) (SubjectReport, error) {
	if subjectID == "" {
		return SubjectReport{}, fmt.Errorf("controlplane: DSAR requires a subject id")
	}
	rep := SubjectReport{SubjectID: subjectID, GeneratedAt: s.now()}

	if err := s.pool.QueryRow(ctx,
		`SELECT count(*), min(appended_at), max(appended_at) FROM audit_entries WHERE subject_id = $1`,
		subjectID).Scan(&rep.AuditEntries.Count, &rep.AuditEntries.FirstAt, &rep.AuditEntries.LastAt); err != nil {
		return SubjectReport{}, fmt.Errorf("controlplane: DSAR audit: %w", err)
	}

	if err := s.pool.QueryRow(ctx,
		`SELECT count(*), coalesce(max(risk_score), 0), min(detected_at), max(detected_at)
		   FROM peer_alerts WHERE subject_id = $1`,
		subjectID).Scan(&rep.PeerAlerts.Count, &rep.PeerAlerts.MaxRisk, &rep.PeerAlerts.FirstAt, &rep.PeerAlerts.LastAt); err != nil {
		return SubjectReport{}, fmt.Errorf("controlplane: DSAR alerts: %w", err)
	}
	rep.PeerAlerts.MaxSeverity = Severity(rep.PeerAlerts.MaxRisk)

	cases, err := s.casesForSubject(ctx, subjectID)
	if err != nil {
		return SubjectReport{}, fmt.Errorf("controlplane: DSAR cases: %w", err)
	}
	rep.Cases = cases

	held, err := s.IsUnderLegalHold(ctx, subjectID)
	if err != nil {
		return SubjectReport{}, fmt.Errorf("controlplane: DSAR legal hold: %w", err)
	}
	rep.UnderLegalHold = held

	return rep, nil
}

// casesForSubject returns the investigation cases opened for a subject, oldest first.
func (s *Server) casesForSubject(ctx context.Context, subjectID string) ([]Case, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, subject_id, status, opened_by, coalesce(assigned_to,''), coalesce(close_requested_by,''),
		        coalesce(closed_by,''), opened_at, closed_at
		   FROM cases WHERE subject_id = $1 ORDER BY opened_at ASC, id ASC`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Case
	for rows.Next() {
		var c Case
		if err := rows.Scan(&c.ID, &c.SubjectID, &c.Status, &c.OpenedBy, &c.AssignedTo,
			&c.CloseRequestedBy, &c.ClosedBy, &c.OpenedAt, &c.ClosedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// subjectHandler serves GET /subject?id=<pseudonymous-subject> — the DSAR report. The requesting
// operator is taken from the VERIFIED client certificate (D56) and the access is RECORDED before
// the report is returned, so no unattributable DSAR occurs. Operator-gated, read-only.
func (s *Server) subjectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	operator := operatorIdentity(r.TLS)
	if operator == "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	subjectID := r.URL.Query().Get("id")
	if subjectID == "" {
		http.Error(w, "missing subject id", http.StatusBadRequest)
		return
	}
	// Record the DSAR access FIRST (like /view) — an attempted access is worth recording even if
	// the read then fails.
	if err := s.RecordView(r.Context(), operator, subjectID, "dsar"); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rep, err := s.SubjectAccessReport(r.Context(), subjectID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, rep)
}
