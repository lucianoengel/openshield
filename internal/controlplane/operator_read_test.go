package controlplane_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// An operator reads peer alerts and overdue agents; an agent (wrong role) is refused.
func TestOperatorReadAPI(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	// Seed a peer alert and a stale agent (old fleet_telemetry row → overdue).
	if _, err := pool.Exec(ctx,
		`INSERT INTO peer_alerts (subject_id, risk_score, context_version, detected_at)
		 VALUES ('sub_abc', 0.97, 'v1', now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, received_at)
		 VALUES ('stale-agent','event','e1','\x00', now() - interval '2 hours')`); err != nil {
		t.Fatal(err)
	}

	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)

	// Operator: /alerts returns the alert.
	op := clientWith(t, ca, "alice", "operator")
	var alerts []controlplane.PeerAlert
	getJSON(t, op, "https://"+addr+"/alerts", &alerts)
	if len(alerts) != 1 || alerts[0].SubjectID != "sub_abc" || alerts[0].RiskScore < 0.9 {
		t.Fatalf("/alerts = %+v, want the seeded peer alert", alerts)
	}

	// Operator: /overdue (threshold 15m) returns the stale agent.
	var overdue []controlplane.AgentStatus
	getJSON(t, op, "https://"+addr+"/overdue?threshold=15m", &overdue)
	found := false
	for _, a := range overdue {
		if a.AgentID == "stale-agent" && a.Overdue {
			found = true
		}
	}
	if !found {
		t.Fatalf("/overdue = %+v, want the stale agent flagged overdue", overdue)
	}

	// Agent role: 403 on both (the operator gate).
	agent := clientWith(t, ca, "bob", "agent")
	for _, path := range []string{"/alerts", "/overdue"} {
		resp, err := agent.Get("https://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("agent %s = %d, want 403 (operator role required)", path, resp.StatusCode)
		}
	}
}

func getJSON(t *testing.T, c *http.Client, url string, v any) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}
