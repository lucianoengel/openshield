// Package runner executes APPROVED response intents against EXTERNAL systems (SOAR-8, ADR-12 Tier-3).
//
// This is the first thing in OpenShield that acts outside itself, and the difference is the whole point.
// D253/D254 enact intents INSIDE the platform — the gateway blocks flows, the endpoint denies execs — and
// both are restored when the intent's TTL lapses. Disabling a user or revoking their sessions in an
// identity provider is IRREVERSIBLE: expiry cannot un-revoke a session. Every control the intent seam has
// so far leans on expiry as the undo, and here there is none, so the controls have to be stronger rather
// than the same.
//
// What that means concretely, and is enforced by the caller in internal/controlplane:
//   - four-eyes is required for EVERY verb this executes, including verbs whose publication needed none;
//   - the runner re-checks that approval itself rather than trusting the publisher;
//   - the action is claimed BEFORE the call, so at-most-once rather than at-least-once;
//   - every call is recorded against the intent id that caused it.
package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Action is the CLOSED vocabulary of things a connector may do.
//
// Closed for the same reason the Action set (D14), the intent verbs and the playbook step registry are: a
// component that can be made to perform an operation nobody enumerated is an open action framework — and
// this one reaches into an identity provider. A test pins the set to exactly these two, so a third cannot
// be added without editing an assertion that says why.
type Action string

const (
	// ActionDisableUser deactivates the subject's account.
	ActionDisableUser Action = "disable-user"
	// ActionRevokeSessions invalidates the subject's live sessions/tokens.
	ActionRevokeSessions Action = "revoke-sessions"
)

// AllActions is the closed vocabulary, for the completeness test.
func AllActions() []Action { return []Action{ActionDisableUser, ActionRevokeSessions} }

// Connector is one external system this runner can drive.
//
// Actions is the connector's DECLARED verb→action mapping. A verb absent from it is IGNORED — "this
// connector does not handle that" is a legitimate answer, not an error to route around, and improvising an
// action for an unmapped verb is precisely what a closed vocabulary exists to prevent.
type Connector struct {
	Name     string
	Endpoint string // operator-configured; the receiver performs the pseudonym→account join (see below)
	Token    string // bearer credential for the endpoint
	Actions  map[corev1.IntentVerb][]Action
	Client   *http.Client
	Timeout  time.Duration
}

// ActionsFor returns what this connector does for a verb, or nothing if it does not declare it.
func (c *Connector) ActionsFor(verb corev1.IntentVerb) []Action {
	if c == nil || c.Actions == nil {
		return nil
	}
	return c.Actions[verb]
}

// callBody is what the receiver gets. The SUBJECT IS THE PSEUDONYM (D23), passed through unresolved.
//
// Resolving it to a directory account here would require a pseudonym→identity table inside the control
// plane — the re-identification surface this whole design avoids — so the join belongs to the deployer, in
// the receiver they configure. The honest consequence: this connector is only useful where that receiver
// can do the mapping.
type callBody struct {
	Action   Action `json:"action"`
	Subject  string `json:"subject"`
	IntentID string `json:"intent_id"`
	Reason   string `json:"reason,omitempty"`
}

// Result is what happened, for the durable record that links intent id → API call.
type Result struct {
	Target string // the URL that was called
	Status int    // the HTTP status returned
}

// Call performs ONE action. It does not retry: an automatic retry of an irreversible call is how one
// failure becomes several, so a failure is returned, recorded, and left for a human.
func (c *Connector) Call(ctx context.Context, action Action, subject, intentID, reason string) (Result, error) {
	target := c.Endpoint
	res := Result{Target: target}
	body, err := json.Marshal(callBody{Action: action, Subject: subject, IntentID: intentID, Reason: reason})
	if err != nil {
		return res, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return res, err
	}
	req.Header.Set("Content-Type", "application/json")
	// The intent id travels in a header as well as the body so a receiver's access log alone links the
	// call back to what authorized it.
	req.Header.Set("X-OpenShield-Intent", intentID)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return res, fmt.Errorf("runner: %s returned %s for %s", c.Name, resp.Status, action)
	}
	return res, nil
}

// IrreversibilityNotice is what an operator is told at startup. Every other intent enactment in the
// platform is restored when the intent lapses, so a reasonable generalisation from those is WRONG here
// unless it is corrected explicitly.
func (c *Connector) IrreversibilityNotice() string {
	return fmt.Sprintf("runner %q is ACTIVE against %s — its actions (%v) are IRREVERSIBLE: intent expiry "+
		"restores nothing here, unlike every other intent enactment in this platform",
		c.Name, c.Endpoint, c.declaredActions())
}

func (c *Connector) declaredActions() []Action {
	seen := map[Action]bool{}
	var out []Action
	for _, acts := range c.Actions {
		for _, a := range acts {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}
