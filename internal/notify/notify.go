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
	"time"
)

// Kind names the two aggregate detections worth paging on. Per-decision alerts are
// deliberately absent (too high-volume) — these are fleet-level signals.
type Kind string

const (
	KindPeerAlert    Kind = "peer-alert"    // a subject anomalous vs its peers (D54)
	KindAgentOverdue Kind = "agent-overdue" // an agent silent past the threshold (D50/D51)
)

// Notification is one alert. Subject and AgentID are pseudonymous (D23) — the
// notification carries no content, only the fleet-level signal.
type Notification struct {
	Kind      Kind      `json:"kind"`
	Subject   string    `json:"subject,omitempty"`
	AgentID   string    `json:"agent_id,omitempty"`
	RiskScore float64   `json:"risk_score,omitempty"`
	At        time.Time `json:"at"`
	Detail    string    `json:"detail,omitempty"`
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
}

// NewWebhook builds a Webhook with a short timeout, so a slow sink cannot stall the
// caller (delivery is best-effort).
func NewWebhook(url string) *Webhook {
	return &Webhook{URL: url, Client: &http.Client{Timeout: 5 * time.Second}}
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
