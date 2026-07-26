package controlplane

import (
	"context"
	"fmt"
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
			{"openshield_unprojected_decisions_total", "Verified alertable decisions not projected into the unified stream — a domain not reaching correlation (XDR-2).", s.UnprojectedDecisions.Load()},
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
	})
}
