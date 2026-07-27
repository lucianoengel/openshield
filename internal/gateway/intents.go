package gateway

import (
	"crypto/ed25519"
	"errors"

	"github.com/nats-io/nats.go"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/intent"
)

// COORDINATED-RESPONSE CONSUMPTION (XDR-6), wired in D294.
//
// `Gateway.intents` was read on every request and assigned by nothing. It is an UNEXPORTED field with no
// setter, so there was not even a way to install one: the branch that overlays a containment onto the
// request's identity context was unreachable in every deployment.
//
// D291 gave the control plane a way to PUBLISH an intent. This is the half that makes publishing mean
// something on the network side — without it, an approved CONTAIN was signed, gated by four eyes, put on
// the wire, and consumed by nobody that enforces.
//
// THE GATEWAY STILL DECIDES. The store supplies CONTEXT its local policy reads; it is not a command
// (T2/D14). A policy that does not read the field is unaffected by any intent, deliberately.

// SubscribeIntents installs a verified intent store and keeps it current from the broker.
//
// The key is the CONTROL PLANE's. An intent that does not verify against it is not from the control
// plane, and containment is a far more attractive forgery target than a risk score — so an unverifiable
// intent is dropped rather than applied, and a gateway with no key consults no intents at all.
func (g *Gateway) SubscribeIntents(conn *nats.Conn, key ed25519.PublicKey) (*nats.Subscription, error) {
	if len(key) == 0 {
		return nil, errors.New("gateway: refusing to consume intents with no control-plane key; an " +
			"unverifiable containment is one anything on the broker could issue")
	}
	store := intent.NewStore()
	sr := intent.NewSubscriber(key, store)
	// ANNOUNCE EVERY APPLIED INTENT. A containment that silently takes effect is one nobody can correlate
	// with the behaviour change it causes, and "we are subscribed" is not the same claim as "we applied
	// one" — a component can announce the first at startup while consuming nothing, which is exactly what
	// a log-line assertion in a test would have accepted.
	sr.SetOnApply(func(in *corev1.ResponseIntent) {
		if g.onIntent != nil {
			g.onIntent(in)
		}
	})
	sub, err := sr.Subscribe(conn)
	if err != nil {
		return nil, err
	}
	g.SetIntents(store)
	return sub, nil
}

// SetIntents installs the store the gateway consults. Exported so a test can drive the overlay without a
// broker, and so the field has a writer at all.
func (g *Gateway) SetIntents(s *intent.IntentStore) { g.intents = s }

// SetIntentObserver installs a callback run for each VERIFIED, applied intent. Used to log the
// enactment; nil is a no-op.
func (g *Gateway) SetIntentObserver(f func(*corev1.ResponseIntent)) { g.onIntent = f }
