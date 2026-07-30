// Package enroll registers an agent identity's public key with the control plane,
// so its subsequently-signed telemetry verifies against an ENROLLED key (D41/D44)
// rather than being self-asserted. Shared by every node that emits signed
// telemetry — the fleet agent and the network gateway.
package enroll

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/identity"
)

// Enroll POSTs the identity's public key to the enrollment endpoint, retrying
// briefly because the control plane may not be up the instant a node starts.
func Enroll(ctx context.Context, client *http.Client, url, agentID, token string, id *identity.Identity) error {
	body, _ := json.Marshal(map[string]string{
		"token": token, "agent_id": agentID,
		"public_key": base64.StdEncoding.EncodeToString(id.PublicKey()),
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		// CANCELLATION IS CHECKED FIRST, and it was not checked at all. The loop only ever asked whether
		// its own 30-second deadline had passed, so a cancelled context made client.Do fail immediately,
		// fall through to an unconditional time.Sleep, and try again — for the full thirty seconds. An
		// agent shutting down blocked here for half a minute, and on a fleet that is half a minute added
		// to every stop and every restart.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("enrollment abandoned: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("building the enrollment request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
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
		// The backoff waits on the context too, so a cancellation during the pause returns promptly
		// instead of sleeping out the remainder.
		select {
		case <-ctx.Done():
			return fmt.Errorf("enrollment abandoned: %w", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}
