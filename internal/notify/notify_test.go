package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/notify"
)

// The webhook POSTs the Notification as JSON with its kind and fields.
func TestWebhookPostsJSON(t *testing.T) {
	var got notify.Notification
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := notify.NewWebhook(srv.URL).Notify(context.Background(), notify.Notification{
		Kind: notify.KindPeerAlert, Subject: "sub_x", RiskScore: 0.95, At: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != notify.KindPeerAlert || got.Subject != "sub_x" || got.RiskScore < 0.9 {
		t.Fatalf("webhook received %+v, want the peer-alert notification", got)
	}
}

// A non-2xx response is an error (surfaced to the best-effort caller).
func TestWebhookNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := notify.NewWebhook(srv.URL).Notify(context.Background(), notify.Notification{Kind: notify.KindAgentOverdue}); err == nil {
		t.Error("a 500 response was not reported as an error")
	}
}

// SIEM-8: a 5xx is TRANSIENT (retried up to the budget), a 4xx is PERMANENT (tried once). This
// exercises the Webhook's classification end-to-end through the retry decorator by counting how
// many requests the receiver actually gets.
func TestWebhookRetryClassification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		wantHits int
	}{
		{"5xx retried to budget", http.StatusServiceUnavailable, 3},
		{"429 retried to budget", http.StatusTooManyRequests, 3},
		{"4xx tried once", http.StatusBadRequest, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits++
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			r := notify.NewRetrying(notify.NewWebhook(srv.URL), 3, time.Millisecond)
			if err := r.Notify(context.Background(), notify.Notification{Kind: notify.KindPeerAlert}); err == nil {
				t.Fatal("a failing sink returned nil")
			}
			if hits != tc.wantHits {
				t.Errorf("receiver got %d requests, want %d", hits, tc.wantHits)
			}
		})
	}
}
