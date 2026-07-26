package controlplane

import (
	"context"
	"time"
)

// Cross-domain entity risk (XDR-7).
//
// Before this, PublishRisk had exactly ONE caller — the server-side peer-UEBA detector — so the risk a
// Zero-Trust access decision reads was purely behavioral. A device with a killed process, a tripped
// ransomware canary and a blocked C2 lookup carried the same risk as a quiet one, because none of those
// domains fed the number. That is the T2 continuous-verification loop (D89/D91) working inside one domain
// and not across them, which is the whole point of having an entity graph and a unified alert stream.
//
// The score is a HEURISTIC wearing a number: severity buckets and a recency weight are a defensible
// ordering, not a calibrated probability of compromise. Nothing downstream may treat it as evidence — the
// policy still decides what a given risk means.

// EntityRiskScore is one entity's aggregated risk and the aliases it should be published to.
type EntityRiskScore struct {
	EntityID int64
	Score    float64
	Aliases  []string
}

// EntityRisk aggregates risk per entity from the unified alert stream.
//
// MAX, not SUM, and that choice is load-bearing: summing makes risk a function of alert VOLUME, so a
// noisy-but-benign asset outranks a quietly-compromised one — and an attacker can keep counts low to stay
// below a threshold. Max asks "what is the worst thing we know about this asset", which is the question an
// access decision is actually asking. Breadth is already XDR-4's job (domain_count on the incident), so
// counting it again here would double-count the same signal.
//
// Recency is a linear decay across the window (weight = 1 − age/window): a critical from an hour ago
// dominates, one from the far end of the window barely registers. Linear because the shape is a heuristic
// either way, and linear is inspectable by an operator reading the number.
func (s *Server) EntityRisk(ctx context.Context, window time.Duration, now time.Time) ([]EntityRiskScore, error) {
	if window <= 0 {
		window = time.Hour
	}
	cutoff := now.Add(-window)
	rows, err := s.pool.Query(ctx,
		`SELECT a.entity_id,
		        max(
		          CASE a.severity WHEN 'critical' THEN 0.90 WHEN 'high' THEN 0.75
		                          WHEN 'medium' THEN 0.50 ELSE 0.25 END
		          * greatest(0, 1 - (extract(epoch from ($2::timestamptz - a.detected_at)) / $3))
		        ) AS score,
		        array_agg(DISTINCT al.value) FILTER (WHERE al.value IS NOT NULL) AS aliases
		   FROM unified_alerts a
		   LEFT JOIN entity_aliases al ON al.entity_id = a.entity_id
		  WHERE a.detected_at >= $1
		  GROUP BY a.entity_id`, cutoff, now.UTC(), window.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EntityRiskScore
	for rows.Next() {
		var e EntityRiskScore
		if err := rows.Scan(&e.EntityID, &e.Score, &e.Aliases); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PublishEntityRisk publishes each entity's aggregated risk to EVERY alias of that entity.
//
// Every alias, because the consumer that matters authorizes on a USER identity (ZT-3) while an endpoint
// alert is keyed by a DEVICE pseudonym: publishing only the device alias would leave the access proxy
// never matching. This is the device⋈user link doing real work rather than only grouping incidents.
func (s *Server) PublishEntityRisk(ctx context.Context, window time.Duration, now time.Time) (int, error) {
	scores, err := s.EntityRisk(ctx, window, now)
	if err != nil {
		return 0, err
	}
	var published int
	for _, e := range scores {
		for _, alias := range e.Aliases {
			if alias == "" {
				continue
			}
			s.PublishRisk(ctx, alias, e.Score)
			published++
		}
	}
	return published, nil
}
