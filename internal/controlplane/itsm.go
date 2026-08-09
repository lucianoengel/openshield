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

// The sync's two halves are DISTINGUISHABLE IN THE ERROR, because an interrupted sync does not mean the
// same thing in both of them and the loop cannot otherwise tell which one it was in.
//
// `ErrTicketUnlinked` is the one that matters. Ticket creation is a remote POST followed by a local link
// row (see openTickets), so a stop landing between the remote 2xx and the INSERT leaves a real ticket in
// someone else's queue with NO local record — and the next tick's `NOT EXISTS` re-selects the incident and
// opens a second one. The stop is still exempt from the counter (this is not a reason to page on every
// restart), but the line has to state the fact a responder can act on rather than a bare phase label.
//
// Wrapping with `%w` is safe for the exemption: both fmt.Errorf/%w and the *url.Error the HTTP client
// returns preserve errors.Is(err, context.Canceled).
var (
	// ErrTicketOpening marks a failure in the ticket-CREATION half of a sync.
	ErrTicketOpening = errors.New("controlplane: opening itsm tickets")
	// ErrTicketUnlinked marks the dangerous window: the remote system ACCEPTED the create and no local
	// link row exists. Unlike every other failure here, the next tick does not reconcile it — its
	// `NOT EXISTS` re-selects the same incident and opens a SECOND ticket, every tick, forever.
	//
	// THREE BRANCHES REACH IT, not one. The obvious one is a failed INSERT after a good create. The other
	// two are inside CreateTicket itself and were missed at first: a 2xx whose body will not decode, and a
	// 2xx carrying no reference (whose own message already said "the incident and the ticket could not be
	// linked"). In all three the ticket exists remotely and cannot be linked, so all three say so.
	ErrTicketUnlinked = errors.New("controlplane: itsm ticket created remotely but its local link was not written")
	// ErrTicketMaybeUnlinked is the HONESTLY UNKNOWN case: the create failed in transport after the body
	// was sent, so the ticketing system may or may not have committed it. It is kept separate from
	// ErrTicketUnlinked because the two call for opposite responses — one needs a ticket closed by hand,
	// the other needs nothing — and collapsing them would send a responder looking for a ticket that
	// probably is not there, which is how a real report gets ignored the next time.
	ErrTicketMaybeUnlinked = errors.New("controlplane: itsm ticket create was interrupted in transport; the remote system may or may not hold a ticket")
	// ErrTicketConfig is a CONFIGURATION failure, not an interrupted operation: no ticket opening was
	// attempted at all. It exists so the record does not claim a phase that never ran.
	ErrTicketConfig = errors.New("controlplane: itsm connector configuration")
	// ErrTicketPolling marks a failure in the status-READBACK half. An interrupted poll leaves nothing
	// behind — the next tick re-reads the same tickets.
	ErrTicketPolling = errors.New("controlplane: polling itsm ticket status")
)

// SyncITSM runs one sync: open tickets for matching incidents, then poll open tickets for closure.
func (s *Server) SyncITSM(ctx context.Context, conn *runner.ITSMConnector) error {
	if conn == nil {
		return errors.New("controlplane: a connector is required")
	}
	if err := s.openTickets(ctx, conn); err != nil {
		return fmt.Errorf("%w: %w", ErrTicketOpening, err)
	}
	if err := s.syncTicketStatuses(ctx, conn); err != nil {
		return fmt.Errorf("%w: %w", ErrTicketPolling, err)
	}
	return nil
}

// openTickets creates a ticket for every matching incident that has none.
func (s *Server) openTickets(ctx context.Context, conn *runner.ITSMConnector) error {
	floor, ok := severityFloor(conn.MinSeverity)
	if !ok {
		// A CONFIGURATION error, and specifically not an interrupted open: nothing was attempted, so a
		// line reading `phase=opening_tickets` would send a responder looking for a half-created ticket
		// that cannot exist. The counter is right either way; the record has to be right too.
		return fmt.Errorf("%w: %q is not a severity", ErrTicketConfig, conn.MinSeverity)
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
			// RETRY IS APPROPRIATE ONLY BEFORE THE REMOTE SYSTEM COMMITS. The comment that used to stand
			// here said a failed attempt "simply retries on the next tick with no duplicate risk", and
			// that is true only for a failure the far side never acted on. CreateTicket now distinguishes
			// the cases where it did.
			switch {
			case errors.Is(err, runner.ErrTicketCreatedUnknownRef):
				// 2xx received: the ticket EXISTS and can never be linked from here, because the
				// reference needed to link it is what went missing.
				return fmt.Errorf("%w (incident %d): %w", ErrTicketUnlinked, p.id, err)
			case errors.Is(err, runner.ErrTicketCreateAmbiguous):
				return fmt.Errorf("%w (incident %d): %w", ErrTicketMaybeUnlinked, p.id, err)
			}
			return err
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO itsm_tickets (connector, incident_id, ticket_ref, ticket_url)
			 VALUES ($1,$2,$3,$4) ON CONFLICT (connector, incident_id) DO NOTHING`,
			conn.Name, p.id, t.Ref, t.URL); err != nil {
			// THE REMOTE TICKET ALREADY EXISTS at this point — CreateTicket returned 2xx above. Failing
			// here is not the harmless retry the comment on CreateTicket's error describes: the next
			// tick's `NOT EXISTS` will re-select this incident and open a SECOND ticket in someone
			// else's queue. Marked so the loop's line says that, instead of "itsm sync failed".
			return fmt.Errorf("%w (incident %d, remote ref %q): %w", ErrTicketUnlinked, p.id, t.Ref, err)
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

// itsmPhase names which half of the sync was interrupted, and — for the one phase whose interruption
// leaves state OUTSIDE this system — states the fact a responder can act on.
//
// The exemption is about not paging, not about the work being safe. Everywhere else here an interrupted
// tick is simply re-attempted when the leader comes back; the unlinked-ticket case is the exception, and
// a line that did not distinguish it would let the exemption disguise an unreconciled remote record as a
// routine stop.
// ORDER IS LOAD-BEARING. Every unlinked/ambiguous/config error is ALSO wrapped in ErrTicketOpening by
// SyncITSM, so the specific cases must be tested first or they all collapse into `phase=opening_tickets`
// — the bland label whose documented meaning ("an interrupted open leaves nothing behind, the next tick
// re-reads") is exactly the wrong thing to tell a responder about an orphaned ticket.
func itsmPhase(err error) []slog.Attr {
	switch {
	case errors.Is(err, ErrTicketUnlinked):
		return []slog.Attr{
			slog.String("phase", "ticket_created_not_linked"),
			// STRING, NOT BOOL, and the sibling case below is why: both branches emit this key, and a
			// bool here against "unknown" there is the same key with two types. A TextHandler does not
			// care; a JSON handler feeding a strict-mapping sink (Elasticsearch, typed Loki) REJECTS the
			// document — and it would reject exactly the two lines carrying the most actionable fact in
			// this file.
			slog.String("remote_state_unreconciled", "yes"),
			slog.String("consequence", "a ticket exists in the remote system with no local link; the "+
				"next sync will open a SECOND ticket for the same incident unless this one is linked "+
				"or closed by hand"),
		}
	case errors.Is(err, ErrTicketMaybeUnlinked):
		return []slog.Attr{
			slog.String("phase", "ticket_create_interrupted"),
			// UNKNOWN, said as unknown. Reporting this as a certain orphan would send someone hunting a
			// ticket that usually is not there; reporting it as harmless would hide the one that is.
			slog.String("remote_state_unreconciled", "unknown"),
			slog.String("consequence", "the create was interrupted in transport after the request was "+
				"sent, so the remote system may or may not hold a ticket for this incident; if it does, "+
				"the next sync will open a second one"),
		}
	case errors.Is(err, ErrTicketConfig):
		return []slog.Attr{
			slog.String("phase", "configuration"),
			slog.String("consequence", "no ticket was opened and none will be until the connector's "+
				"configuration is corrected — this is not an interrupted operation"),
		}
	case errors.Is(err, ErrTicketOpening):
		return []slog.Attr{slog.String("phase", "opening_tickets")}
	case errors.Is(err, ErrTicketPolling):
		return []slog.Attr{slog.String("phase", "polling_status")}
	}
	return nil
}

// RunITSMLoop syncs on an interval. LEADER-ONLY, like every other integration: several replicas syncing
// would open duplicate tickets in someone else's system.
func (s *Server) RunITSMLoop(ctx context.Context, interval time.Duration,
	conn *runner.ITSMConnector, log *slog.Logger) {
	retain.Loop(ctx, interval, func(c context.Context) {
		if err := s.SyncITSM(c, conn); err != nil {
			NoteTickErr(ctx, log, "itsm sync failed", &ITSMFailures, err, itsmPhase(err)...)
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
