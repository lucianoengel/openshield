package controlplane

import (
	"fmt"
	"net/http"
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
			{"openshield_dropped_messages_total", "NATS async errors / slow-consumer drops (receive-side loss, SEC-4).", s.DroppedMessages.Load()},
		}
		for _, m := range metrics {
			fmt.Fprintf(w, "# HELP %s %s\n", m.name, m.help)
			fmt.Fprintf(w, "# TYPE %s counter\n", m.name)
			fmt.Fprintf(w, "%s %d\n", m.name, m.val)
		}
	})
}
