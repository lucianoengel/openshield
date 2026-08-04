//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// CONSOLE-7 AGAINST THE SHIPPED BINARY.
//
// The package tests can set leadership directly and assert the report carries it. What they CANNOT prove
// is that anything ever calls `SetLeaderHeld` — the election lives in `cmd/openshield-server`, and a
// field that only tests write is the exact shape this repo has found in D313, D415, D417, D418, D470 and
// CONSOLE-1's own `/report/response`. `leader: true` here comes from the real election, or not at all.

func TestTheHealthReportIsReachableAndItsLeadershipIsReal(t *testing.T) {
	p := newPKI(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)

	addr := "127.0.0.1:" + freePort(t)
	Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
	}, tlsEnv(m)...))
	waitTCP(t, addr, 60*time.Second)

	analyst := p.operator(t, "analyst", "health-watcher")
	var report struct {
		Leader            bool     `json:"leader"`
		DatabaseReachable bool     `json:"database_reachable"`
		BrokerConnected   bool     `json:"broker_connected"`
		BrokerConfigured  bool     `json:"broker_configured"`
		SchemaEmbedded    int      `json:"schema_embedded"`
		SchemaApplied     int      `json:"schema_applied"`
		SchemaSkew        int      `json:"schema_skew"`
		Degraded          bool     `json:"degraded"`
		Problems          []string `json:"problems"`
	}

	// A SINGLE INSTANCE BECOMES LEADER IMMEDIATELY, but the election is asynchronous, so poll rather
	// than sleep — and fail with the last body seen, since "leader was false" and "the route 404'd" need
	// completely different responses.
	var last string
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := analyst.Get("https://" + addr + "/health")
		if err != nil {
			t.Fatalf("GET /health: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /health = %d %s — the operator tier could not reach the health report, which is "+
				"the whole ticket: every health fact lived behind the separate /metrics token",
				resp.StatusCode, strings.TrimSpace(string(body)))
		}
		last = string(body)
		if err := json.Unmarshal(body, &report); err != nil {
			t.Fatalf("parsing %q: %v", last, err)
		}
		if report.Leader || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !report.Leader {
		t.Fatalf("the only instance in this stack never reported leadership: %s\n"+
			"Either the election did not complete, or SetLeaderHeld is never called by the binary — and "+
			"the second is a field that only tests write", last)
	}
	if !report.DatabaseReachable {
		t.Errorf("the database is reachable and the report says otherwise: %s", last)
	}
	// The facts are GATHERED, not zero-valued. A report of all zeros is indistinguishable from one that
	// could not read anything and concluded nothing was wrong.
	if report.SchemaEmbedded == 0 || report.SchemaApplied == 0 {
		t.Errorf("schema counts are zero (embedded=%d applied=%d): %s",
			report.SchemaEmbedded, report.SchemaApplied, last)
	}
	if report.SchemaSkew != 0 {
		t.Errorf("schema skew = %d against a freshly migrated stack: %s", report.SchemaSkew, last)
	}
	if report.BrokerConfigured && !report.BrokerConnected {
		t.Errorf("the broker is configured and reported disconnected: %s", last)
	}
	if report.Degraded != (len(report.Problems) > 0) {
		t.Errorf("degraded=%v with %d problems: %s", report.Degraded, len(report.Problems), last)
	}

	// AND IT IS BEHIND THE OPERATOR GATE. A health report naming the schema state, the broker and the
	// anchor history is infrastructure detail, not a public liveness probe.
	//
	// THE REFUSAL MAY COME FROM EITHER LAYER, and both are correct. This deployment configures no
	// identity provider and no machine tokens, so the listener demands a client certificate at the
	// HANDSHAKE and an anonymous caller never reaches HTTP at all — a stronger refusal than 401, and the
	// one an operator-only deployment gets. With bearer credentials enabled the handshake succeeds and
	// the tier gate answers 401 instead. Asserting only the status code would fail against the stricter
	// posture, which is precisely backwards.
	anon := p.bearerClient(t)
	resp, err := anon.Get("https://" + addr + "/health")
	if err != nil {
		if !strings.Contains(err.Error(), "certificate required") {
			t.Errorf("anonymous GET /health failed for an unexpected reason: %v", err)
		}
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Errorf("an unauthenticated caller read the health report: %d", resp.StatusCode)
	}
}
