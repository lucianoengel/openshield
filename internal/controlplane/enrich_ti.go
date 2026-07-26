package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/nips"
)

// Incident threat-intel enrichment (SOAR-5).
//
// NO NEW COLUMN AND NO NEW PRIVACY SURFACE. Everything this needs is already persisted:
//
//	incident → incident_alerts (XDR-5) → unified_alerts.event_id (the XDR-5 evidence reference)
//	        → the VERIFIED fleet_telemetry event → NetworkSubject{sni_host, dst_ip, http_path}
//
// That is the same discipline that made the response-intent id ride `Context.Version` instead of adding a
// hashed ledger column (D254): look for the field that already exists before collecting anything new. The
// observable therefore inherits the retention the event already has, and no destination is stored twice.
//
// ONLY VERIFIED EVENTS COUNT (D44). Unverified telemetry is not evidence. If it could steer enrichment,
// anyone able to publish unsigned telemetry could manufacture a "TI-confirmed" incident — or bury a real
// one in noise — without holding a key.
//
// A HIT ANNOTATES AND NOTHING ELSE: no alert raised, no severity changed, no lifecycle advanced, no
// intent published. A public feed is a third party's assertion, and one over-broad entry (a CDN domain, a
// shared NAT address) would otherwise become fleet-wide enforcement. Annotation puts the fact in front of
// a human, which is what a threat-intel hit is actually worth.

// TIHit is one threat-intel match on an incident's evidence.
type TIHit struct {
	Category  string   // ioc-domain | ioc-ip | uri-signature
	Indicator string   // the matched indicator, as the feed spells it
	Feeds     []string // which feed(s) assert it — corroboration is information
}

// tiCategoryName maps the shared matcher's category to the closed label an annotation carries. It mirrors
// the ThreatCategory enum the inline engine reports, so an analyst reading an annotation and an analyst
// reading a NIPS decision see the same vocabulary.
func tiCategoryName(c nips.Category) string {
	switch c {
	case nips.CategoryDomain:
		return "ioc-domain"
	case nips.CategoryIP:
		return "ioc-ip"
	case nips.CategoryURI:
		return "uri-signature"
	default:
		return "unknown"
	}
}

// EnrichIncidentWithTI matches an incident's evidence observables against the IOC store and returns the
// hits. It reads only; recording is the caller's (the playbook step's) job.
func (s *Server) EnrichIncidentWithTI(ctx context.Context, incidentID int64) ([]TIHit, error) {
	feed, err := s.FeedFromStore(ctx)
	if err != nil {
		return nil, err
	}
	if feed.Size() == 0 {
		// No threat intel ingested: nothing to say. Not an error — a deployment without a feed behaves
		// exactly as it did before this existed.
		return nil, nil
	}
	observables, err := s.incidentObservables(ctx, incidentID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var hits []TIHit
	for _, o := range observables {
		// THE SHARED MATCHER. Re-implementing this here is the mistake the whole design avoids: the
		// parent-suffix domain rule, the CIDR containment and the minimum-URI guard live in nips.Feed
		// and must not be spelled twice.
		for _, m := range feed.Match(o.host, o.dstIP, o.path) {
			key := tiCategoryName(m.Category) + "|" + m.IndicatorID
			if seen[key] {
				continue
			}
			seen[key] = true
			hits = append(hits, TIHit{
				Category:  tiCategoryName(m.Category),
				Indicator: m.IndicatorID,
				Feeds:     s.feedForIndicator(ctx, indicatorKindFor(m.Category, m.IndicatorID), m.IndicatorID),
			})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Category != hits[j].Category {
			return hits[i].Category < hits[j].Category
		}
		return hits[i].Indicator < hits[j].Indicator
	})
	return hits, nil
}

// indicatorKindFor recovers the store's kind for a matched indicator. An IP-category match may have come
// from an exact address or from a CIDR the address falls inside; the matcher reports the CIDR's own
// string in that case, so a '/' distinguishes them without guessing.
func indicatorKindFor(c nips.Category, indicator string) string {
	switch c {
	case nips.CategoryDomain:
		return nips.KindDomain
	case nips.CategoryIP:
		if strings.Contains(indicator, "/") {
			return nips.KindCIDR
		}
		return nips.KindIP
	case nips.CategoryURI:
		return nips.KindURI
	default:
		return ""
	}
}

// observable is one flow's network metadata, as the event already recorded it.
type observable struct {
	host  string
	dstIP string
	path  string
}

// incidentObservables walks the incident's contributing alerts to their evidence events and extracts the
// network metadata those events already carry.
func (s *Server) incidentObservables(ctx context.Context, incidentID int64) ([]observable, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT a.event_id FROM incident_alerts ia
		   JOIN unified_alerts a ON a.id = ia.alert_id
		  WHERE ia.incident_id = $1 AND a.event_id IS NOT NULL`, incidentID)
	if err != nil {
		return nil, err
	}
	var eventIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		eventIDs = append(eventIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []observable
	for _, id := range eventIDs {
		o, ok, err := s.networkObservable(ctx, id)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, o)
		}
	}
	return out, nil
}

// networkObservable loads a VERIFIED event and returns its network metadata.
//
// The `AND verified` predicate is the security property, not a filter: it is the same one
// `originatingEvent` uses, and dropping it would let unsigned telemetry decide what the platform
// believes about an incident.
func (s *Server) networkObservable(ctx context.Context, eventID string) (observable, bool, error) {
	var payload []byte
	err := s.pool.QueryRow(ctx,
		`SELECT payload FROM fleet_telemetry WHERE kind='event' AND event_id=$1 AND verified ORDER BY id LIMIT 1`,
		eventID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return observable{}, false, nil
	}
	if err != nil {
		return observable{}, false, err
	}
	var ev corev1.Event
	if err := proto.Unmarshal(payload, &ev); err != nil {
		s.DecodeFailures.Add(1)
		return observable{}, false, nil
	}
	n := ev.GetNetwork()
	if n == nil {
		return observable{}, false, nil // not a network event: nothing to match
	}
	return observable{host: n.GetSniHost(), dstIP: n.GetDstIp(), path: n.GetHttpPath()}, true, nil
}

// tiAnnotationBody renders hits for an operator. It names the indicator and the feed that asserts it,
// because "known bad" without a source is not something an analyst can act on or dispute.
func tiAnnotationBody(hits []TIHit) string {
	parts := make([]string, 0, len(hits))
	for _, h := range hits {
		feeds := "unattributed"
		if len(h.Feeds) > 0 {
			feeds = strings.Join(h.Feeds, ",")
		}
		parts = append(parts, fmt.Sprintf("%s=%s (feed: %s)", h.Category, h.Indicator, feeds))
	}
	return "threat intel: " + strings.Join(parts, "; ")
}
