package controlplane

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lucianoengel/openshield/internal/notify"
)

// Cross-domain correlation (XDR-4). The burst rule (Correlate) groups the single-domain UEBA
// `peer_alerts` table by SUBJECT STRING. This rule groups the multi-domain `unified_alerts` stream by
// the XDR graph ENTITY — which is the whole point: one asset is named differently by different domains
// (the endpoint knows a device pseudonym, the access proxy knows a user identity, the graph links them),
// so grouping by subject would split a single asset into several and the multi-domain condition would
// never be met for exactly the attacks this rule exists to catch.
//
// The two rules coexist. This is additive: nothing about the burst rule, peer_alerts, or SOAR-1's
// paging behavior changes.

// IncidentKindUEBABurst / IncidentKindCrossDomain discriminate the two rules' incidents in one table.
// A representative subject is stored for display on both, so the open-incident uniqueness index is
// scoped by kind — otherwise the two rules' incidents for one asset would collide and the second upsert
// would silently overwrite the first.
const (
	IncidentKindUEBABurst   = "ueba_burst"
	IncidentKindCrossDomain = "cross_domain"
)

// CrossDomainRule parameterizes the entity-keyed rule. All fields have safe defaults.
type CrossDomainRule struct {
	Window      time.Duration // look-back window (default 1h)
	MinDomains  int           // distinct domains within the window to raise an incident (default 2)
	MinSeverity string        // ignore alerts below this severity bucket ("" = no floor)
	// Sequence is an optional ORDERED domain sequence (e.g. ueba→hips→nips) that the entity's alerts
	// must contain as a subsequence. Empty = no ordering constraint (the plain multi-domain rule).
	Sequence []string
}

// CrossDomainIncident is a correlated multi-domain group of alerts for ONE entity.
type CrossDomainIncident struct {
	EntityID    int64     `json:"entity_id"`
	SubjectID   string    `json:"subject_id"` // a representative subject, for display only
	AlertCount  int       `json:"alert_count"`
	DomainCount int       `json:"domain_count"`
	Severity    string    `json:"severity"` // max contributing bucket, escalated by domain breadth
	Domains     []string  `json:"domains"`  // distinct domains, in first-seen order
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	// AlertIDs are the contributing unified alerts, in detection order (XDR-5). Recorded at
	// materialization so an incident's evidence set is what the correlation ACTUALLY saw — recomputing it
	// at read time would let the set silently shrink as alerts aged out of the window.
	AlertIDs []int64 `json:"-"`
}

// severityRank orders the four buckets so "the highest severity among these alerts" and "one bucket
// higher" are total operations over the existing vocabulary (ADR-10) rather than a second scale.
// An unrecognized label ranks lowest — an unknown bucket must never silently outrank a known one.
func severityRank(sev string) int {
	switch sev {
	case SeverityCritical:
		return 3
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 1
	case SeverityLow:
		return 0
	default:
		return -1
	}
}

var severityByRank = [4]string{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// maxSeverity returns the highest bucket present. An empty list, or one with no recognized bucket, is
// `low` — the conservative answer, never an invented one.
func maxSeverity(severities []string) string {
	best := -1
	for _, s := range severities {
		if r := severityRank(s); r > best {
			best = r
		}
	}
	if best < 0 {
		return SeverityLow
	}
	return severityByRank[best]
}

// escalateSeverity raises a base bucket ONE step per distinct domain beyond the first, capped at
// critical. Breadth is the signal this rule exists to surface: three domains lighting up on one asset is
// qualitatively different from three alerts in one domain, and an operator sorting by severity should
// see it.
//
// This is triage ORDERING, not evidence. A correlated incident is not a confirmed true positive —
// confidence, not certainty (D4).
func escalateSeverity(base string, domainCount int) string {
	r := severityRank(base)
	if r < 0 {
		r = 0 // an unrecognized base starts at the bottom rather than being trusted
	}
	if domainCount > 1 {
		r += domainCount - 1
	}
	if r > 3 {
		r = 3
	}
	return severityByRank[r]
}

// matchesSequence reports whether `want` appears in `ordered` as an ORDERED SUBSEQUENCE — the steps in
// order, with unrelated domains allowed in between.
//
// Set containment ("all these domains fired") is deliberately NOT what this does. An attack narrative is
// an ordering claim: identity-anomaly THEN exec THEN DNS is a story, while the same three in reverse is
// noise that happens to share a domain set. Accepting the reverse order would make the rule claim
// something materially stronger than it can support.
//
// An empty `want` matches everything (no ordering constraint requested).
func matchesSequence(ordered, want []string) bool {
	if len(want) == 0 {
		return true
	}
	i := 0
	for _, d := range ordered {
		if d == want[i] {
			i++
			if i == len(want) {
				return true
			}
		}
	}
	return false
}

// distinctInOrder returns the distinct values of a sequence in first-seen order — the incident's domain
// list, stable for display and for a test to assert against.
func distinctInOrder(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// CorrelateCrossDomain runs the entity-keyed multi-domain rule over `unified_alerts` and returns
// incidents, highest severity first.
//
// The split of work is deliberate: SQL does the set-based part it is good at (group by entity, count
// distinct domains, order the alerts), and the RULE LOGIC — the ordered-subsequence match, the severity
// escalation — is pure Go over the aggregated slices, so every branch is unit-testable without a
// database. The ordering semantics are the subtle part of this ticket, and they are far easier to prove
// correct in Go than in a correlated subquery.
//
// Only alerts inside the window are considered: this does NOT retro-correlate alerts that predate it.
func (s *Server) CorrelateCrossDomain(ctx context.Context, rule CrossDomainRule, now time.Time) ([]CrossDomainIncident, error) {
	window := rule.Window
	if window <= 0 {
		window = time.Hour
	}
	minDomains := rule.MinDomains
	if minDomains <= 0 {
		minDomains = 2 // "cross-domain" means at least two; one domain is the burst rule's job
	}
	cutoff := now.Add(-window)
	// The severity floor is applied IN the query, before the domain count is taken — so a domain count
	// can never be satisfied by alerts that the floor then excluded (which would report a breadth the
	// qualifying alerts do not have).
	minRank := severityRank(rule.MinSeverity)
	if rule.MinSeverity == "" {
		minRank = -1 // no floor
	}

	rows, err := s.pool.Query(ctx,
		`SELECT entity_id, count(*), count(DISTINCT domain), min(detected_at), max(detected_at),
		        array_agg(domain   ORDER BY detected_at, id),
		        array_agg(severity ORDER BY detected_at, id),
		        (array_agg(subject_id ORDER BY detected_at, id))[1],
		        array_agg(id ORDER BY detected_at, id)
		   FROM unified_alerts
		  WHERE detected_at >= $1
		    AND CASE severity WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1
		                      WHEN 'low' THEN 0 ELSE -1 END >= $2
		  GROUP BY entity_id
		 HAVING count(DISTINCT domain) >= $3`, cutoff, minRank, minDomains)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CrossDomainIncident
	for rows.Next() {
		var (
			inc        CrossDomainIncident
			domains    []string
			severities []string
		)
		if err := rows.Scan(&inc.EntityID, &inc.AlertCount, &inc.DomainCount,
			&inc.FirstSeen, &inc.LastSeen, &domains, &severities, &inc.SubjectID, &inc.AlertIDs); err != nil {
			return nil, err
		}
		if !matchesSequence(domains, rule.Sequence) {
			continue
		}
		inc.Domains = distinctInOrder(domains)
		inc.Severity = escalateSeverity(maxSeverity(severities), inc.DomainCount)
		out = append(out, inc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Highest severity first, then widest breadth — the triage order an operator reads top-down.
	sortBySeverityThenBreadth(out)
	return out, nil
}

// sortBySeverityThenBreadth orders incidents for triage. Insertion sort: the result set is one row per
// correlating entity, so this is small by construction, and an explicit stable order beats an ORDER BY
// over a computed-in-Go severity.
func sortBySeverityThenBreadth(in []CrossDomainIncident) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0; j-- {
			a, b := in[j-1], in[j]
			ra, rb := severityRank(a.Severity), severityRank(b.Severity)
			if ra > rb || (ra == rb && a.DomainCount >= b.DomainCount) {
				break
			}
			in[j-1], in[j] = b, a
		}
	}
}

// MaterializeCrossDomainIncidents runs the cross-domain rule and persists each incident, upserting the
// ENTITY's open cross-domain incident (one per entity): a re-correlation extends the open incident
// rather than duplicating it.
//
// It reuses the burst rule's page-once mechanism verbatim — RETURNING (xmax = 0) distinguishes a genuine
// INSERT from the DO UPDATE path, and only an insert pages (SOAR-1/D220). Without that, every scheduled
// re-run would re-page an incident a human already saw.
func (s *Server) MaterializeCrossDomainIncidents(ctx context.Context, rule CrossDomainRule, now time.Time) (int, error) {
	incidents, err := s.CorrelateCrossDomain(ctx, rule, now)
	if err != nil {
		return 0, err
	}
	for _, inc := range incidents {
		var id int64
		var inserted bool
		if err := s.pool.QueryRow(ctx,
			`INSERT INTO incidents (kind, subject_id, entity_id, state, alert_count, max_risk, host_count,
			                        domain_count, domains, first_seen, last_seen)
			 VALUES ('cross_domain',$1,$2,'open',$3,0,0,$4,$5,$6,$7)
			 ON CONFLICT (entity_id) WHERE state = 'open' AND kind = 'cross_domain'
			 DO UPDATE SET alert_count = EXCLUDED.alert_count, domain_count = EXCLUDED.domain_count,
			              domains = EXCLUDED.domains,
			              subject_id = EXCLUDED.subject_id, last_seen = EXCLUDED.last_seen,
			              first_seen = LEAST(incidents.first_seen, EXCLUDED.first_seen), updated_at = now()
			 RETURNING id, (xmax = 0) AS inserted`,
			inc.SubjectID, inc.EntityID, inc.AlertCount, inc.DomainCount, inc.Domains,
			inc.FirstSeen, inc.LastSeen).
			Scan(&id, &inserted); err != nil {
			return 0, err
		}
		// XDR-5: record WHICH alerts this incident is made of, so it has a timeline. ON CONFLICT DO
		// NOTHING on the composite key makes a re-correlation CONVERGE: the same alerts are seen again
		// every tick, and the evidence set must be the union — without it a scheduled correlation loop
		// would multiply every incident's evidence on every run.
		if len(inc.AlertIDs) > 0 {
			if _, err := s.pool.Exec(ctx,
				`INSERT INTO incident_alerts (incident_id, alert_id)
				 SELECT $1, unnest($2::bigint[]) ON CONFLICT DO NOTHING`, id, inc.AlertIDs); err != nil {
				return 0, err
			}
		}
		if inserted {
			s.notifyCrossDomainIncident(ctx, id, inc, now)
		}
	}
	return len(incidents), nil
}

// notifyCrossDomainIncident pages a human that a NEW cross-domain incident was raised. The detail names
// the breadth, which is the reason this incident exists at all. max_risk is deliberately not part of it:
// unified alerts carry a severity bucket, not a continuous risk score, and reporting a 0.00 risk would
// be a false statement about a signal this rule never computed.
func (s *Server) notifyCrossDomainIncident(ctx context.Context, id int64, inc CrossDomainIncident, now time.Time) {
	s.emit(ctx, notify.Notification{
		Kind:    notify.KindIncident,
		Subject: inc.SubjectID,
		At:      now,
		// Namespaced by kind so a cross-domain incident and a burst incident can never share a
		// dedup id (the two tables' autoincrements are one sequence, but the ids are not the same
		// logical alert).
		ID: fmt.Sprintf("xinc_%d", id),
		Detail: fmt.Sprintf("%s cross-domain incident: %d alerts across %d domains (%s)",
			inc.Severity, inc.AlertCount, inc.DomainCount, strings.Join(inc.Domains, ", ")),
	})
}
