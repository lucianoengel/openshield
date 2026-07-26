package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	"crypto/ed25519"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/intent"
	"github.com/lucianoengel/openshield/internal/runner"
)

// Executing an approved intent against an EXTERNAL system (SOAR-8, ADR-12 Tier-3).
//
// The ordering below is the design. Each check is here rather than somewhere upstream for a reason:
//
//  1. the connector must DECLARE the verb (a closed vocabulary — an unmapped verb is ignored, not
//     improvised);
//  2. the intent must still be VALID (an expired containment is not authority to disable an account);
//  3. an approval bound to THIS intent id must be APPROVED — for every verb, re-checked HERE;
//  4. the action is CLAIMED before the call, so at-most-once;
//  5. the outcome is recorded against the intent id.

// ErrIntentNotApproved is REUSED from the publication path rather than redeclared: "no approved
// four-eyes approval for this intent id" is the same refusal whether it stops a publication or an
// execution, and one sentinel means a caller cannot handle one and miss the other.
var (
	// ErrIntentLapsed means the intent's own validity has ended.
	ErrIntentLapsed = errors.New("controlplane: the intent is not in effect")
	// ErrAlreadyEnacted means this connector already handled this intent.
	ErrAlreadyEnacted = errors.New("controlplane: the intent was already enacted by this connector")
)

// EnactIntent executes an intent against a connector, if every control passes.
//
// FOUR-EYES IS REQUIRED FOR EVERY VERB HERE, INCLUDING ONES PUBLICATION DOES NOT GATE. `PublishIntents`
// gates only high-impact verbs, and that is right for a signal a local policy interprets — gating
// everything trains operators to rubber-stamp. It is NOT right for a component that reaches into an
// identity provider and takes an action expiry cannot undo.
//
// And the check happens HERE rather than being inherited from publication. Trusting the publisher would
// put the authorization check in the component that ASKS for the action rather than the one that PERFORMS
// it — and any path delivering an intent to this runner without going through PublishIntents would bypass
// it entirely.
//
// The approval is bound to the intent id, so approval to revoke trust for one subject can never authorize
// another: that is what SOAR-3's (kind, id) keying is for.
func (s *Server) EnactIntent(ctx context.Context, conn *runner.Connector, in *corev1.ResponseIntent) (int, error) {
	if conn == nil || in == nil {
		return 0, errors.New("controlplane: a connector and an intent are required")
	}
	actions := conn.ActionsFor(in.GetVerb())
	if len(actions) == 0 {
		// The connector does not declare this verb. Not an error, and deliberately NOT recorded: there is
		// nothing to explain to anyone, and a row would imply something happened.
		return 0, nil
	}
	if exp := in.GetExpiresAt(); exp != nil && !exp.AsTime().After(s.now()) {
		// An expired intent is not authority. Checked BEFORE the approval lookup so a lapsed intent
		// cannot be resurrected by an approval that outlives it.
		return 0, fmt.Errorf("%w: %s", ErrIntentLapsed, in.GetIntentId())
	}
	a, err := s.ApprovalFor(ctx, ApprovalSubjectResponseIntent, in.GetIntentId())
	if err != nil || a.State != ApprovalApproved {
		return 0, fmt.Errorf("%w: intent %s", ErrIntentNotApproved, in.GetIntentId())
	}

	// CLAIM BEFORE CALLING. At-most-once, not at-least-once: for "disable this account", a duplicate on
	// redelivery is the failure that gets a SOAR turned off. The cost — a crash between claim and call
	// leaves an action never performed and not retried — is paid in a visible `claimed` row rather than
	// hidden.
	claimed, rowID, err := s.claimEnactment(ctx, conn.Name, in, actions[0])
	if err != nil {
		return 0, err
	}
	if !claimed {
		return 0, fmt.Errorf("%w: %s", ErrAlreadyEnacted, in.GetIntentId())
	}

	done := 0
	for _, action := range actions {
		res, callErr := conn.Call(ctx, action, in.GetSubject(), in.GetIntentId(), in.GetReason())
		if callErr != nil {
			// No retry: an automatic retry of an irreversible call is how one failure becomes several.
			// The failure and its cause are recorded against the intent id, for a human.
			s.recordEnactment(ctx, rowID, "failed", res, callErr)
			return done, callErr
		}
		done++
		s.recordEnactment(ctx, rowID, "executed", res, nil)
	}
	return done, nil
}

// claimEnactment takes the at-most-once claim. ON CONFLICT DO NOTHING makes it atomic — whichever caller
// claims first is the only one that calls, with no read-then-write race.
func (s *Server) claimEnactment(ctx context.Context, connector string, in *corev1.ResponseIntent,
	action runner.Action) (bool, int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO runner_actions (connector, intent_id, verb, subject, action, state, at)
		 VALUES ($1,$2,$3,$4,$5,'claimed',$6)
		 ON CONFLICT (connector, intent_id) DO NOTHING
		 RETURNING id`,
		connector, in.GetIntentId(), in.GetVerb().String(), in.GetSubject(), string(action), s.now()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		// The insert conflicted: this connector already handled this intent. Not an error — the whole
		// point of the unique index is that a redelivery is a no-op rather than a second disable.
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	return true, id, nil
}

// recordEnactment writes the outcome onto the claimed row: what was called, and what came back.
func (s *Server) recordEnactment(ctx context.Context, rowID int64, state string, res runner.Result, cause error) {
	msg := ""
	if cause != nil {
		msg = truncate(cause.Error(), 512)
	}
	_, _ = s.pool.Exec(ctx,
		`UPDATE runner_actions SET state=$2, target=$3, http_status=$4, error=$5 WHERE id=$1`,
		rowID, state, res.Target, res.Status, msg)
}

// EnactedAction is one recorded external action, for an operator asking "what did we do, and what
// authorized it?".
type EnactedAction struct {
	Connector  string    `json:"connector"`
	IntentID   string    `json:"intent_id"`
	Verb       string    `json:"verb"`
	Subject    string    `json:"subject"`
	Action     string    `json:"action"`
	Target     string    `json:"target"`
	State      string    `json:"state"`
	HTTPStatus int       `json:"http_status"`
	Error      string    `json:"error,omitempty"`
	At         time.Time `json:"at"`
}

// EnactmentsForIntent returns what was done under an intent id — the link the ticket exists to provide.
func (s *Server) EnactmentsForIntent(ctx context.Context, intentID string) ([]EnactedAction, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT connector, intent_id, verb, subject, action, target, state, http_status, error, at
		   FROM runner_actions WHERE intent_id=$1 ORDER BY id`, intentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnactedAction
	for rows.Next() {
		var a EnactedAction
		if err := rows.Scan(&a.Connector, &a.IntentID, &a.Verb, &a.Subject, &a.Action, &a.Target,
			&a.State, &a.HTTPStatus, &a.Error, &a.At); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetIntentResponder installs the connector this control plane enacts approved intents with (SOAR-8).
//
// It lives on the Server rather than in main because the Server owns the NATS connection; Run wires the
// subscription. The verification key is REQUIRED: an intent that does not verify against the control
// plane's own key is not from the control plane, and an unverifiable intent must never disable an account.
func (s *Server) SetIntentResponder(key ed25519.PublicKey, conn *runner.Connector) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.responderKey, s.responder = key, conn
}

// subscribeIntentResponder wires the runner onto the live NATS connection, if one is configured. Called
// from Run. A missing key or connector means the responder simply does not exist — never a partial one.
func (s *Server) subscribeIntentResponder(conn *nats.Conn) error {
	s.mu.Lock()
	key, rc := s.responderKey, s.responder
	s.mu.Unlock()
	if rc == nil || len(key) == 0 {
		return nil
	}
	sub := intent.NewSubscriber(key, intent.NewStore())
	sub.SetOnApply(func(in *corev1.ResponseIntent) {
		// Every control lives in EnactIntent: the connector must DECLARE the verb, the intent must be
		// unexpired, a four-eyes approval bound to THIS intent id must be approved, the action is claimed
		// at-most-once, and the outcome is recorded. A refusal is logged and never retried.
		if n, err := s.EnactIntent(context.Background(), rc, in); err != nil {
			s.RunnerRefusals.Add(1)
			fmt.Fprintf(os.Stderr, "openshield-server: %s refused intent %s: %v\n",
				rc.Name, in.GetIntentId(), err)
		} else if n > 0 {
			s.RunnerActions.Add(int64(n))
			fmt.Fprintf(os.Stderr, "openshield-server: %s performed %d IRREVERSIBLE action(s) under "+
				"intent %s\n", rc.Name, n, in.GetIntentId())
		}
	})
	nsub, err := sub.Subscribe(conn)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.subs = append(s.subs, nsub)
	s.mu.Unlock()
	fmt.Fprintln(os.Stderr, "openshield-server: "+rc.IrreversibilityNotice())
	return nil
}
