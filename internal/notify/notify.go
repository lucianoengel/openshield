// Package notify delivers alerts to a human — the missing half of "detection"
// (D83). The control plane records peer-UEBA alerts and computes overdue agents;
// this pushes them to a configured sink so a security team is told, not left to
// poll with psql.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Kind names the aggregate detections worth paging on. Per-decision alerts are
// deliberately absent (too high-volume) — these are fleet-level signals: a peer
// anomaly, a silent agent, or a correlated incident (SOAR-1).
type Kind string

const (
	KindPeerAlert    Kind = "peer-alert"    // a subject anomalous vs its peers (D54)
	KindAgentOverdue Kind = "agent-overdue" // an agent silent past the threshold (D50/D51)
	KindIncident     Kind = "incident"      // a correlated incident was raised (SOAR-1); pseudonymous, no content
	// KindApprovalPending is a four-eyes request waiting on a human (SOAR-9, closing SOAR-3's residual).
	// Without it a request waits for someone who was never told — and a playbook step gated on approval
	// (SOAR-4) parks indefinitely on a decision nobody knows is pending.
	KindApprovalPending Kind = "approval-pending"
	// KindEscalation is an incident that has gone unacknowledged past a configured deadline (SOAR-9b).
	// It is a SEPARATE kind, not a re-send of KindIncident, because the whole point of escalating is to
	// reach somewhere the first notification did not — and routing keys on kind. Sent to the same
	// destination as the page nobody answered, it would be a louder version of being ignored.
	KindEscalation Kind = "escalation"
	// KindConfigWeakened is a configuration change that moved the deployment TOWARD LESS DETECTION
	// (SEC-A) — a longer silence tolerated before an agent is called missing, a shorter evidence
	// retention, a destination added to a detector's allowlist.
	//
	// It is a detection in its own right, not an administrative log entry, because the threat it
	// addresses is an operator credential being used to blind the product before the thing it would
	// have caught. Nobody reads a config-change history at the moment that matters, which is why this
	// goes to the channel that reaches whoever is on call.
	KindConfigWeakened Kind = "config-weakened"
)

// Notification is one alert. Subject and AgentID are pseudonymous (D23) — the
// notification carries no content, only the fleet-level signal.
type Notification struct {
	// ID is a stable idempotency key for this logical alert (SIEM-12). A receiver dedupes on it, so a
	// client-timeout-after-server-success retry does not double-page. It is stable across the
	// delivery retry (the same Notification is retried), and distinct per logical alert.
	ID        string  `json:"id,omitempty"`
	Kind      Kind    `json:"kind"`
	Subject   string  `json:"subject,omitempty"`
	AgentID   string  `json:"agent_id,omitempty"`
	RiskScore float64 `json:"risk_score,omitempty"`
	// Severity is the triage bucket this notification ROUTES on (SOAR-9). The producer sets it, or the
	// control plane's emit stamps it from the risk score — the risk→bucket MAPPING stays in one place
	// (SIEM-6) and is deliberately not duplicated in this package.
	Severity string    `json:"severity,omitempty"`
	At       time.Time `json:"at"`
	Detail   string    `json:"detail,omitempty"`
}

// Notifier delivers a Notification. Implementations are best-effort from the
// caller's view — the caller logs and continues on error (D30: the alert is already
// recorded; delivery is additive).
type Notifier interface {
	Notify(ctx context.Context, n Notification) error
}

// Nop is the default: it delivers nowhere. Notification is opt-in — a deployer
// configures a sink to turn it on.
type Nop struct{}

func (Nop) Notify(context.Context, Notification) error { return nil }

// Webhook POSTs the Notification as JSON to a URL. A deployer bridges it to
// Slack/PagerDuty/email with an off-the-shelf receiver — one adapter, no vendor
// coupling.
type Webhook struct {
	URL    string
	Client *http.Client
	// Secret, when non-empty, HMAC-signs the request body (SIEM-8) so a receiver can
	// verify the alert genuinely came from this control plane. Empty = unsigned (the
	// body and headers are byte-for-byte unchanged from the pre-signing behavior).
	Secret []byte
	// now stamps the signature timestamp (SIEM-8b); injectable for tests. Defaults to time.Now.
	now func() time.Time
}

// NewWebhook builds a Webhook with a short timeout, so a slow sink cannot stall the
// caller (delivery is best-effort).
func NewWebhook(url string) *Webhook {
	return &Webhook{URL: url, Client: &http.Client{Timeout: 5 * time.Second}, now: time.Now}
}

func (w *Webhook) Notify(ctx context.Context, n Notification) error {
	body, err := json.Marshal(n)
	if err != nil {
		return Permanent(err) // a notification that will not serialize will not serialize on retry
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return Permanent(err) // a bad URL is not fixed by retrying
	}
	req.Header.Set("Content-Type", "application/json")
	// Authenticate the payload (SIEM-8) and bind it to a timestamp so a captured delivery cannot be
	// replayed (SIEM-8b): sign "<ts>."+body over the EXACT bytes sent and send the timestamp too.
	// Only when a secret is configured — otherwise no headers, body byte-for-byte unchanged.
	if len(w.Secret) > 0 {
		clock := w.now
		if clock == nil {
			clock = time.Now
		}
		ts := clock().Unix()
		req.Header.Set(TimestampHeader, strconv.FormatInt(ts, 10))
		req.Header.Set(SignatureHeader, Sign(w.Secret, ts, body))
	}
	resp, err := w.Client.Do(req)
	if err != nil {
		return err // transport error (timeout, refused) — transient, retryable
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		werr := fmt.Errorf("notify: webhook returned %d", resp.StatusCode)
		// A 4xx (except 429 Too Many Requests) is a client error — a bad URL, auth, or payload —
		// that retrying will not fix, so mark it permanent. 429 and 5xx are transient.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return Permanent(werr)
		}
		return werr
	}
	return nil
}
