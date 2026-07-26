package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/lucianoengel/openshield/internal/retain"
	"github.com/lucianoengel/openshield/internal/runner"
)

// Incident ⇄ ticket sync (SOAR-8 increment 2).
//
// The team doing the work tracks it in a ticketing system, and without this the two drift: the incident
// stays `open` here forever because closing it is a second manual step nobody remembers.
//
// POLLING, NOT A WEBHOOK. A webhook is lower-latency and is what most ITSMs offer — and it needs an
// authenticated inbound route a third-party SaaS can reach, which is a new trust boundary and one that
// cannot sit behind the operator-mTLS gate every other route here uses (D55/D58). Polling needs no inbound
// surface. The honest cost, stated rather than hidden: sync-back lags by up to one poll interval.

// ITSMFailures counts sync ticks that errored — a silent integration is one nobody notices has stopped.
var ITSMFailures atomic.Int64

// SyncITSM runs one sync: open tickets for matching incidents, then poll open tickets for closure.
func (s *Server) SyncITSM(ctx context.Context, conn *runner.ITSMConnector) error {
	if conn == nil {
		return errors.New("controlplane: a connector is required")
	}
	if err := s.openTickets(ctx, conn); err != nil {
		return err
	}
	return s.syncTicketStatuses(ctx, conn)
}

// openTickets creates a ticket for every matching incident that has none.
func (s *Server) openTickets(ctx context.Context, conn *runner.ITSMConnector) error {
	floor, ok := severityFloor(conn.MinSeverity)
	if !ok {
		return fmt.Errorf("controlplane: %q is not a severity", conn.MinSeverity)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, subject_id, alert_count, max_risk, host_count
		   FROM incidents i
		  WHERE i.max_risk >= $1 AND i.state <> 'closed'
		    AND NOT EXISTS (SELECT 1 FROM itsm_tickets t
		                     WHERE t.connector = $2 AND t.incident_id = i.id)
		  ORDER BY i.id`, floor, conn.Name)
	if err != nil {
		return err
	}
	type pending struct {
		id                    int64
		subject               string
		alertCount, hostCount int
		risk                  float64
	}
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.subject, &p.alertCount, &p.risk, &p.hostCount); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, p := range todo {
		sev := Severity(p.risk)
		// METADATA ONLY (D10/D29): the pseudonymous subject, the severity bucket and counts. A ticketing
		// system is usually the least access-controlled place an incident ever reaches, so evidence
		// content must not travel here.
		t, err := conn.CreateTicket(ctx, runner.TicketRequest{
			IncidentID: p.id,
			Subject:    p.subject,
			Severity:   sev,
			AlertCount: p.alertCount,
			HostCount:  p.hostCount,
			Summary: fmt.Sprintf("OpenShield incident %d: %s, %d alert(s) across %d host(s)",
				p.id, sev, p.alertCount, p.hostCount),
		})
		if err != nil {
			// Retry IS appropriate here, unlike the IdP responder: creation is driven by a "no ticket
			// yet" query, so a failed attempt simply retries on the next tick with no duplicate risk.
			return err
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO itsm_tickets (connector, incident_id, ticket_ref, ticket_url)
			 VALUES ($1,$2,$3,$4) ON CONFLICT (connector, incident_id) DO NOTHING`,
			conn.Name, p.id, t.Ref, t.URL); err != nil {
			return err
		}
	}
	return nil
}

// syncTicketStatuses polls each ticket for an incident that is not yet closed, and closes the incident
// when the remote status is one the connector DECLARES as closed.
func (s *Server) syncTicketStatuses(ctx context.Context, conn *runner.ITSMConnector) error {
	rows, err := s.pool.Query(ctx,
		`SELECT t.id, t.incident_id, t.ticket_ref
		   FROM itsm_tickets t JOIN incidents i ON i.id = t.incident_id
		  WHERE t.connector = $1 AND i.state <> 'closed' ORDER BY t.id`, conn.Name)
	if err != nil {
		return err
	}
	type live struct {
		rowID, incidentID int64
		ref               string
	}
	var tickets []live
	for rows.Next() {
		var l live
		if err := rows.Scan(&l.rowID, &l.incidentID, &l.ref); err != nil {
			rows.Close()
			return err
		}
		tickets = append(tickets, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, t := range tickets {
		status, err := conn.TicketStatus(ctx, t.ref)
		if err != nil {
			return err
		}
		// The observed status is recorded even when it is one we do NOT recognise — that record is what
		// lets an operator see a remote vocabulary change, instead of wondering why nothing ever closes.
		if _, err := s.pool.Exec(ctx,
			`UPDATE itsm_tickets SET last_status=$2, last_synced_at=now() WHERE id=$1`,
			t.rowID, status); err != nil {
			return err
		}
		if !conn.MeansClosed(status) {
			// A status outside the declared set is IGNORED, never assumed to mean closed. If a remote
			// system renames a status, the fail-safe direction is "keep investigating", not "stop".
			continue
		}
		// THE CONNECTOR IS THE ACTOR, never an operator identity. TransitionIncident stamps the
		// acknowledgement on the first move off `open` (D258), so an incident going straight from open to
		// closed via a ticket would otherwise record a PERSON as having acknowledged it — a corrupted
		// audit trail, and corrupted acknowledgement attribution for the response metrics.
		err = s.TransitionIncident(ctx, t.incidentID, IncidentClosed, "itsm:"+conn.Name)
		switch {
		case err == nil, errors.Is(err, ErrBackwardTransition):
			// A backward move is a NO-OP, not an error: forward-only (D250) is an invariant the metrics
			// depend on, and an external system does not get to override it. A reopened ticket is a
			// legitimate thing for a human to do — it simply does not move this incident.
		case errors.Is(err, ErrIncidentNotFound):
			// The incident was purged; the ticket outlives it. Nothing to do.
		default:
			return err
		}
	}
	return nil
}

// RunITSMLoop syncs on an interval. LEADER-ONLY, like every other integration: several replicas syncing
// would open duplicate tickets in someone else's system.
func (s *Server) RunITSMLoop(ctx context.Context, interval time.Duration,
	conn *runner.ITSMConnector, log *slog.Logger) {
	retain.Loop(ctx, interval, func(c context.Context) {
		if err := s.SyncITSM(c, conn); err != nil {
			ITSMFailures.Add(1)
			if log != nil {
				log.Error("itsm sync failed", slog.Any("err", err))
			}
		}
	})
}

// TicketForIncident returns the ticket linked to an incident, or nil.
func (s *Server) TicketForIncident(ctx context.Context, connector string, incidentID int64) (*IncidentTicket, error) {
	var t IncidentTicket
	err := s.pool.QueryRow(ctx,
		`SELECT connector, incident_id, ticket_ref, ticket_url, last_status, created_at, last_synced_at
		   FROM itsm_tickets WHERE connector=$1 AND incident_id=$2`, connector, incidentID).
		Scan(&t.Connector, &t.IncidentID, &t.Ref, &t.URL, &t.LastStatus, &t.CreatedAt, &t.LastSyncedAt)
	if err != nil {
		return nil, nil
	}
	return &t, nil
}

// IncidentTicket links an incident to its ticket in both directions.
type IncidentTicket struct {
	Connector    string     `json:"connector"`
	IncidentID   int64      `json:"incident_id"`
	Ref          string     `json:"ticket_ref"`
	URL          string     `json:"ticket_url,omitempty"`
	LastStatus   string     `json:"last_status,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"`
}
