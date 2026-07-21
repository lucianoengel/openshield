package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Case / investigation workflow (Phase F3). An operator opens a case on a pseudonymous
// subject, assigns it, adds notes, and closes it — but CLOSING is a FOUR-EYES action
// (D36): one operator requests closure and a DIFFERENT operator approves it, so no single
// operator can unilaterally close (and bury) an investigation. Every actor is the
// operator's VERIFIED certificate identity (D56), never a self-asserted string.

// ErrFourEyes is returned when the same operator tries to both request and approve a
// closure — the four-eyes control refusing a single-operator close.
var ErrFourEyes = errors.New("cases: closure requires a second operator (four-eyes, D36)")

// Case is an investigation record.
type Case struct {
	ID               int64      `json:"id"`
	SubjectID        string     `json:"subject_id"`
	Status           string     `json:"status"`
	OpenedBy         string     `json:"opened_by"`
	AssignedTo       string     `json:"assigned_to,omitempty"`
	CloseRequestedBy string     `json:"close_requested_by,omitempty"`
	ClosedBy         string     `json:"closed_by,omitempty"`
	OpenedAt         time.Time  `json:"opened_at"`
	ClosedAt         *time.Time `json:"closed_at,omitempty"`
}

// OpenCase starts an investigation of a subject, attributed to the opening operator.
func (s *Server) OpenCase(ctx context.Context, subjectID, operator string) (int64, error) {
	if subjectID == "" || operator == "" {
		return 0, fmt.Errorf("cases: subject and operator are required")
	}
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO cases (subject_id, opened_by) VALUES ($1,$2) RETURNING id`,
		subjectID, operator).Scan(&id)
	return id, err
}

// AssignCase assigns an open case to an operator.
func (s *Server) AssignCase(ctx context.Context, id int64, assignee string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE cases SET assigned_to = $1 WHERE id = $2 AND status <> 'closed'`, assignee, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("cases: case %d not found or already closed", id)
	}
	return nil
}

// AddNote appends an attributed note to a case.
func (s *Server) AddNote(ctx context.Context, id int64, author, note string) error {
	if note == "" {
		return fmt.Errorf("cases: empty note")
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO case_notes (case_id, author, note) VALUES ($1,$2,$3)`, id, author, note)
	return err
}

// RequestClose records an operator's request to close a case. It does NOT close it — a
// second, different operator must approve (four-eyes, D36).
func (s *Server) RequestClose(ctx context.Context, id int64, operator string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE cases SET status = 'close_requested', close_requested_by = $1
		  WHERE id = $2 AND status <> 'closed'`, operator, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("cases: case %d not found or already closed", id)
	}
	return nil
}

// ApproveClose closes a case whose closure was requested — but ONLY when the approver is a
// DIFFERENT operator than the requester (four-eyes, D36). An approver equal to the
// requester is refused with ErrFourEyes. The comparison is done in the UPDATE predicate so
// it is atomic: two operators racing cannot both slip through.
func (s *Server) ApproveClose(ctx context.Context, id int64, approver string) error {
	// Refuse up front for a clear error, AND enforce in the predicate for atomicity.
	var requester, status string
	err := s.pool.QueryRow(ctx, `SELECT status, coalesce(close_requested_by,'') FROM cases WHERE id = $1`, id).
		Scan(&status, &requester)
	if err != nil {
		return fmt.Errorf("cases: case %d not found: %w", id, err)
	}
	if status != "close_requested" {
		return fmt.Errorf("cases: case %d is not awaiting closure (status %q)", id, status)
	}
	if approver == requester {
		return ErrFourEyes
	}
	ct, err := s.pool.Exec(ctx,
		`UPDATE cases SET status = 'closed', closed_by = $1, closed_at = now()
		  WHERE id = $2 AND status = 'close_requested' AND close_requested_by <> $1`,
		approver, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		// The predicate rejected it — either a race changed the state or the approver is
		// the requester (four-eyes). Report the four-eyes violation, the security case.
		return ErrFourEyes
	}
	return nil
}

// GetCase reads a case by id.
func (s *Server) GetCase(ctx context.Context, id int64) (*Case, error) {
	var c Case
	err := s.pool.QueryRow(ctx,
		`SELECT id, subject_id, status, opened_by, coalesce(assigned_to,''),
		        coalesce(close_requested_by,''), coalesce(closed_by,''), opened_at, closed_at
		   FROM cases WHERE id = $1`, id).
		Scan(&c.ID, &c.SubjectID, &c.Status, &c.OpenedBy, &c.AssignedTo,
			&c.CloseRequestedBy, &c.ClosedBy, &c.OpenedAt, &c.ClosedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
