package controlplane

import (
	"context"
	"fmt"
	"github.com/lucianoengel/openshield/internal/connectors/syslog"
	"net/http"
	"time"
)

// MetricsHandler serves the control plane's operational counters in the Prometheus text
// exposition format (PLAT-4). OTel was deliberately cut from Phase 1 (brief); this is a
// deliberate re-opening for enterprise operability, kept DEPENDENCY-FREE (a hand-written
// exposition, no client library) so it adds no supply-chain surface.
//
// It exposes the "no silent loss" counters the system already maintains — dropped/rejected/
// gapped telemetry — so an operator can ALERT on them, turning the project's internal
// honesty counters into an external signal. The values are counts only (no subject, no
// content), so the endpoint leaks nothing (D10/D29); it is unauthenticated by convention
// (Prometheus scrapes it) and belongs on an internal/firewalled address.
func (s *Server) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// The aggregate is computed BEFORE anything is written, so the "degrade, never fail" decision is
		// EXPLICIT rather than an accident of write ordering. (Querying after the first Write would make
		// a non-200 impossible anyway — the status is already committed — which would leave the property
		// structurally true but untestable, and a later refactor could silently lose it.)
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		hist, histErr := s.responseHistograms(ctx)
		fleet, fleetErr := s.fleetEnforcementMetrics(ctx)

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		metrics := []struct {
			name, help string
			val        int64
		}{
			{"openshield_decode_failures_total", "Messages that did not decode (dropped, counted).", s.DecodeFailures.Load()},
			{"openshield_rejected_telemetry_total", "Signed telemetry that failed verification (bad sig/unknown/revoked/replay).", s.RejectedTelemetry.Load()},
			{"openshield_telemetry_gaps_total", "Sequence gaps in verified telemetry (suppression between agent and here).", s.Gaps.Load()},
			{"openshield_peer_alerts_total", "Server-side peer-UEBA detections recorded.", s.PeerAlerts.Load()},
			{"openshield_notify_failures_total", "Alert-delivery errors (best-effort delivery).", s.NotifyFailures.Load()},
			{"openshield_notify_dropped_total", "Notifications dropped because the async delivery queue was full (SIEM-12).", s.NotifyDropped.Load()},
			{"openshield_notify_deduped_total", "Duplicate notifications suppressed by the server-side idempotency check (SIEM-12).", s.NotifyDeduped.Load()},
			{"openshield_dropped_messages_total", "NATS async errors / slow-consumer drops (receive-side loss, SEC-4).", s.DroppedMessages.Load()},
			{"openshield_unified_alert_failures_total", "Unified-alert projections that could not be recorded (XDR-2).", s.UnifiedAlertFailures.Load()},
			{"openshield_schema_skew", "Migrations the DATABASE has applied that this binary does not embed (PLAT-9) — non-zero means a binary rollback left this process reading a schema ahead of it.", SchemaSkew.Load()},
			{"openshield_runner_actions_total", "IRREVERSIBLE external actions performed under an approved intent (SOAR-8) — these are not undone by intent expiry.", s.RunnerActions.Load()},
			{"openshield_runner_refusals_total", "Intents the runner declined (unapproved, expired, undeclared verb, already enacted) — a responder that silently does nothing looks identical to one that works, without this.", s.RunnerRefusals.Load()},
			{"openshield_notify_unrouted_total", "Notifications that matched NO routing rule and were therefore delivered to every sink (SOAR-9) — a non-zero value means the routing table has a hole.", s.NotifyUnrouted()},
			{"openshield_unprojected_decisions_total", "Verified alertable decisions not projected into the unified stream — a domain not reaching correlation (XDR-2).", s.UnprojectedDecisions.Load()},

			// EXTERNAL-LOG INGEST (SIEM-4/9). These were incremented from the day they were written and
			// rendered by nothing — while a comment beside them claimed they were already on /metrics and
			// that dashboards depended on them. A counter that is not exposed gives the appearance of the
			// "never silent" property and none of its substance, and the failure is invisible precisely
			// because the counter looks present in the code.
			{"openshield_cef_ingested_total", "External syslog logs (CEF or RFC 5424) persisted.", s.CEFIngested.Load()},
			{"openshield_cef_dropped_total", "External syslog datagrams NEITHER parser accepted, or whose persistence failed — a non-zero value means a log source is sending something this deployment cannot read, and its events are absent from every hunt.", s.CEFDropped.Load()},
			{"openshield_cloudtrail_ingested_total", "CloudTrail records persisted.", s.CloudTrailIngested.Load()},
			{"openshield_cloudtrail_dropped_total", "CloudTrail records skipped — a non-zero value means part of the cloud audit trail is not searchable here.", s.CloudTrailDropped.Load()},
			{"openshield_wef_ingested_total", "Windows Event Forwarding records persisted.", s.WEFIngested.Load()},
			{"openshield_wef_dropped_total", "Windows Event Forwarding records skipped — a non-zero value means Windows endpoints are reporting events this deployment is discarding.", s.WEFDropped.Load()},

			{"openshield_entity_resolve_failures_total", "Entity-graph writes that failed — a non-zero value means some device or user is NOT in the graph, so cross-domain correlation cannot join on it and an attack spanning that entity surfaces as separate incidents (XDR-1).", s.EntityResolveFailures.Load()},
			{"openshield_decision_contract_violations_total", "Decisions REFUSED for not satisfying the decision contract (D350) — an action outside the closed set, an absent or out-of-range confidence, or no identifying policy. A non-zero value means an enrolled agent is sending decisions this build cannot reason about: a version skew, or a compromised agent attempting to forge severity.", s.DecisionContractViolations.Load()},
			{"openshield_retention_record_failures_total", "Retention/purge outcomes that could not be recorded — the purge may have run, but the compliance evidence that it ran is missing (T-013).", s.RetentionRecordFailures.Load()},
		}
		// LISTENER REFUSALS, appended only when a listener is actually running. These count what was
		// turned away BEFORE it became a countable event, so they cannot be derived from the ingest
		// counters above: an admission-limited datagram never reaches CEFDropped.
		if l, ok := s.cefDatagram.Load().(*syslog.Listener); ok && l != nil {
			metrics = append(metrics,
				struct {
					name, help string
					val        int64
				}{"openshield_syslog_rate_limited_total", "Syslog datagrams refused by the admission rate limit (NIPS-7) — a non-zero value means a sender is outrunning this listener and its events are NOT in the store.", l.RateLimited()},
				struct {
					name, help string
					val        int64
				}{"openshield_syslog_unparsed_total", "Syslog datagrams no parser accepted — a device is sending a dialect this deployment cannot read.", l.Dropped()})
		}
		if l, ok := s.cefStream.Load().(*syslog.StreamListener); ok && l != nil {
			metrics = append(metrics,
				struct {
					name, help string
					val        int64
				}{"openshield_syslog_stream_rate_limited_total", "Stream syslog messages refused by the admission rate limit.", l.RateLimited()},
				struct {
					name, help string
					val        int64
				}{"openshield_syslog_stream_oversize_total", "Stream syslog messages REFUSED for exceeding the line bound — actionable as 'sender X sent 9KB against an 8KB bound', unlike a parse failure.", l.Oversize()},
				struct {
					name, help string
					val        int64
				}{"openshield_syslog_stream_unparsed_total", "Stream syslog messages no parser accepted.", l.Dropped()})
		}

		for _, m := range metrics {
			fmt.Fprintf(w, "# HELP %s %s\n", m.name, m.help)
			fmt.Fprintf(w, "# TYPE %s counter\n", m.name)
			fmt.Fprintf(w, "%s %d\n", m.name, m.val)
		}
		// SOAR-6 response histograms.
		//
		// A FAILURE IS NOT AN ERROR RESPONSE. The counters above are what the "no silent loss" alerts
		// fire on; failing the scrape because an aggregate did not compute would take alerting down with
		// it — a reporting problem becoming an outage in the very system that would have reported the
		// outage. So: emit what we have, omit what we could not, and SAY SO in a comment line the scraper
		// ignores, because a silent omission is indistinguishable from a healthy zero.
		if histErr != nil {
			fmt.Fprintf(w, "# response metrics unavailable: %v\n", histErr)
			return
		}
		fmt.Fprint(w, hist)
		// Same degradation rule: emit what we have, say what we could not compute. A scrape that fails
		// takes alerting down with it.
		if fleetErr != nil {
			fmt.Fprintf(w, "# fleet enforcement state unavailable: %v\n", fleetErr)
			return
		}
		fmt.Fprint(w, fleet)
	})
}
