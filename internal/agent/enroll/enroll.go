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
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
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
		time.Sleep(500 * time.Millisecond)
	}
}
