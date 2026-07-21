package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrNoViewer is returned when a view is recorded without an identity — no
// unattributable view may be silently recorded (D20).
var ErrNoViewer = errors.New("controlplane: view requires a viewer identity")

// ViewRecord is one recorded investigation view.
type ViewRecord struct {
	Viewer        string
	SubjectFilter string
	EventID       string
	ViewedAt      time.Time
}

// RecordView writes that an investigation was viewed. The viewer must carry an
// identity — callers pass "unauthenticated:<os-user>" until operator
// authentication exists, so a self-asserted OS identity is never mistaken for a
// verified operator. It is NOT the evidentiary ledger (D41-style caveat).
func (s *Server) RecordView(ctx context.Context, viewer, subjectFilter, eventID string) error {
	if viewer == "" {
		return ErrNoViewer
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO investigation_views (viewer, subject_filter, event_id) VALUES ($1,$2,$3)`,
		viewer, subjectFilter, eventID)
	return err
}

// View serves an investigation AND records the view in one call, so a caller
// cannot obtain the evidence without leaving a record. The view is recorded
// FIRST — an attempted view is more worth recording than a failed read is worth
// hiding.
func (s *Server) View(ctx context.Context, viewer, eventID string) ([]TelemetryRow, error) {
	if viewer == "" {
		return nil, ErrNoViewer
	}
	if err := s.RecordView(ctx, viewer, "", eventID); err != nil {
		return nil, fmt.Errorf("controlplane: recording view: %w", err)
	}
	return s.TelemetryForEvent(ctx, eventID)
}

// Views returns recorded views for an event, oldest first.
func (s *Server) Views(ctx context.Context, eventID string) ([]ViewRecord, error) {
	return s.viewQuery(ctx, `SELECT viewer, subject_filter, event_id, viewed_at
		FROM investigation_views WHERE event_id = $1 ORDER BY id ASC`, eventID)
}

// ViewsBy returns recorded views by a viewer, oldest first.
func (s *Server) ViewsBy(ctx context.Context, viewer string) ([]ViewRecord, error) {
	return s.viewQuery(ctx, `SELECT viewer, subject_filter, event_id, viewed_at
		FROM investigation_views WHERE viewer = $1 ORDER BY id ASC`, viewer)
}

func (s *Server) viewQuery(ctx context.Context, sql, arg string) ([]ViewRecord, error) {
	rows, err := s.pool.Query(ctx, sql, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ViewRecord
	for rows.Next() {
		var v ViewRecord
		if err := rows.Scan(&v.Viewer, &v.SubjectFilter, &v.EventID, &v.ViewedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
