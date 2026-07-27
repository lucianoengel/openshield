package engine

import (
	"crypto/ed25519"
	"errors"

	"github.com/nats-io/nats.go"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/intent"
)

// COORDINATED-RESPONSE CONSUMPTION on the ENDPOINT (XDR-6), wired in D294.
//
// `SetIntentResolver` existed, was tested, and had no caller — so an endpoint consulted no intent, and
// the local policy's ResponseIntent field was never populated in any deployment. Together with the
// gateway's unassigned store, that meant an approved CONTAIN reached NEITHER enforcement component: the
// whole point of XDR-6 is that ONE approved containment is enacted by the gateway on flows and by the
// endpoint on execs, stamping the same intent id, and neither half was listening.
func (e *Engine) SubscribeIntents(conn *nats.Conn, key ed25519.PublicKey) (*nats.Subscription, error) {
	if len(key) == 0 {
		return nil, errors.New("engine: refusing to consume intents with no control-plane key")
	}
	store := intent.NewStore()
	sr := intent.NewSubscriber(key, store)
	// ANNOUNCE EVERY APPLIED INTENT. A containment that silently takes effect is one nobody can correlate
	// with the behaviour change it causes, and "we are subscribed" is not the same claim as "we applied
	// one" — a component can announce the first at startup while consuming nothing, which is exactly what
	// a log-line assertion in a test would have accepted.
	sr.SetOnApply(func(in *corev1.ResponseIntent) {
		if e.onIntent != nil {
			e.onIntent(in)
		}
	})
	sub, err := sr.Subscribe(conn)
	if err != nil {
		return nil, err
	}
	// Expiry is evaluated by the store ON READ, so a stale containment cannot outlive its TTL even if the
	// control plane that issued it is gone. That is why the resolver reads through Current() per event
	// rather than caching a verb.
	e.SetIntentResolver(func(subject string) (corev1.IntentVerb, string, bool) {
		in := store.Current(subject)
		if in == nil {
			return corev1.IntentVerb_INTENT_VERB_UNSPECIFIED, "", false
		}
		return in.GetVerb(), in.GetIntentId(), true
	})
	return sub, nil
}

// SetIntentObserver installs a callback run for each VERIFIED, applied intent. Used to log the
// enactment; nil is a no-op.
func (e *Engine) SetIntentObserver(f func(*corev1.ResponseIntent)) { e.onIntent = f }
