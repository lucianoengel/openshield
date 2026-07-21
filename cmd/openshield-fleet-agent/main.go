// Command openshield-fleet-agent is the fleet-facing half of an agent, for the
// fleet simulation (Direction 1). It generates a per-agent identity, enrols over
// HTTP (D51), then publishes SIGNED telemetry and heartbeats (D50/D42) on an
// interval — exercising identity → enroll → verified telemetry → liveness.
//
// It does NOT classify files or run the pipeline (that is the engine); it exists
// to demonstrate the fleet CONTROL path across real containers.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

func main() {
	agentID := env("OPENSHIELD_AGENT_ID", "fleet-agent")
	enrollURL := env("OPENSHIELD_ENROLL_URL", "http://127.0.0.1:8080/enroll")
	token := os.Getenv("OPENSHIELD_ENROLL_TOKEN")
	natsURL := env("OPENSHIELD_NATS_URL", "nats://127.0.0.1:4222")
	interval := envDuration("OPENSHIELD_HEARTBEAT", 2*time.Second)
	// The pseudonymous subject this agent's activity is attributed to (D23), and
	// how many events it emits per tick — a high burst makes an agent a peer-UEBA
	// OUTLIER relative to the fleet (D54).
	subject := env("OPENSHIELD_SUBJECT", agentID)
	burst := envInt("OPENSHIELD_BURST", 1)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	id, err := identity.Generate(agentID)
	if err != nil {
		fatal("identity: %v", err)
	}
	if err := enroll(ctx, enrollURL, agentID, token, id); err != nil {
		fatal("enroll: %v", err)
	}
	fmt.Fprintf(os.Stderr, "fleet-agent %s enrolled\n", agentID)

	conn, err := nats.Connect(natsURL)
	if err != nil {
		fatal("nats: %v", err)
	}
	defer conn.Close()
	pub := natsx.NewSignedPublisher(agentID, id, conn)

	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_ = pub.PublishHeartbeat(ctx, &corev1.Heartbeat{AgentId: agentID, ObservedAt: timestamppb.Now()})
			for i := 0; i < burst; i++ {
				_ = pub.PublishEvent(ctx, &corev1.Event{EventId: agentID + "-ev", AgentId: agentID,
					Kind:    corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
					Subject: &corev1.Subject{PseudonymousId: subject}})
			}
		}
	}
}

func enroll(ctx context.Context, url, agentID, token string, id *identity.Identity) error {
	body, _ := json.Marshal(map[string]string{
		"token": token, "agent_id": agentID,
		"public_key": base64.StdEncoding.EncodeToString(id.PublicKey()),
	})
	// Retry briefly — the endpoint may not be up the instant the container starts.
	deadline := time.Now().Add(30 * time.Second)
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("enroll status %d", resp.StatusCode)
			}
		} else if time.Now().After(deadline) {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "fleet-agent: "+f+"\n", a...)
	os.Exit(1)
}
