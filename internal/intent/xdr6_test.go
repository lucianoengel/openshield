package intent_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/intent"
	"github.com/lucianoengel/openshield/internal/policy"
)

// XDR-6: ONE approved CONTAIN intent, consumed by BOTH local policies — the gateway's (flows) and the
// endpoint's (execs) — with both enactments stamping the SAME intent id, and TTL expiry restoring both.
//
// The endpoint's kernel-level half is proven on a real kernel in internal/agent/execipc (D253). What this
// test proves is the COORDINATION property XDR-6 is actually about: one intent, two independent local
// decisions, one traceable id, and a clean expiry — with two REAL OPA policies, one per domain.

const gatewayFlowPolicy = `package openshield
import rego.v1
contained if { input.context.has_response_intent; input.context.response_intent == "INTENT_VERB_CONTAIN" }
decision := {"action":"BLOCK","reason":"entity contained","confidence":0.99} if { contained }
decision := {"action":"ALLOW","reason":"not contained","confidence":0.9} if { not contained }`

const endpointExecPolicy = `package openshield
import rego.v1
contained if { input.context.has_response_intent; input.context.response_intent == "INTENT_VERB_CONTAIN" }
decision := {"action":"DENY_EXEC","reason":"entity contained","confidence":0.99} if { contained }
decision := {"action":"ALLOW","reason":"not contained","confidence":0.9} if { not contained }`

// decide runs one real policy over the context the resolver produced.
func decide(t *testing.T, rego string, ctx *core.Context, ev *corev1.Event) *corev1.Decision {
	t.Helper()
	pol, err := policy.New(context.Background(), "xdr6", "1", rego)
	if err != nil {
		t.Fatal(err)
	}
	st := &core.State{Event: ev, Context: ctx}
	out, err := pol.Run(context.Background(), st)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if out.Decision == nil {
		t.Fatal("policy produced no decision")
	}
	return out.Decision
}

// contextFor mirrors what the gateway and the engine resolvers build: the intent's verb AND its id, the id
// carried as the Context version so it reaches the Decision and the ledger (D27) without a schema change.
func contextFor(store *intent.IntentStore, subject string) *core.Context {
	in := store.Current(subject)
	if in == nil {
		return &core.Context{ComputedAt: time.Now()}
	}
	return &core.Context{
		Version: in.GetIntentId(), ResponseIntent: in.GetVerb(), HasResponseIntent: true,
		ComputedAt: time.Now(),
	}
}

func TestOneContainIntentIsEnactedByBothDomainsUnderOneID(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	store := intent.NewStore()
	sub := intent.NewSubscriber(pub, store)

	const subject = "sub_entity_E"
	const intentID = "INTENT_VERB_CONTAIN:sub_entity_E:29000000"

	flowEvent := &corev1.Event{EventId: "flow-1", Kind: corev1.EventKind_EVENT_KIND_NETWORK_FLOW,
		Subject: &corev1.Subject{PseudonymousId: subject},
		Target:  &corev1.Event_Network{Network: &corev1.NetworkSubject{DstIp: "10.0.0.9", Protocol: "tcp"}}}
	execEvent := &corev1.Event{EventId: "exec-1", Kind: corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
		Subject: &corev1.Subject{PseudonymousId: subject},
		Target:  &corev1.Event_Process{Process: &corev1.ProcessSubject{Pid: 4242, ExecPath: "/bin/curl"}}}

	// BEFORE any intent: both domains allow. Otherwise "contains everything" would be indistinguishable
	// from "enacts a containment".
	if got := decide(t, gatewayFlowPolicy, contextFor(store, subject), flowEvent); got.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("with no intent the gateway decided %v, want ALLOW", got.GetAction())
	}
	if got := decide(t, endpointExecPolicy, contextFor(store, subject), execEvent); got.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("with no intent the endpoint decided %v, want ALLOW", got.GetAction())
	}

	// ONE signed CONTAIN arrives, and both domains consume the SAME intent.
	if err := sub.Apply(signedContain(t, priv, intentID, subject, time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}

	gwDec := decide(t, gatewayFlowPolicy, contextFor(store, subject), flowEvent)
	epDec := decide(t, endpointExecPolicy, contextFor(store, subject), execEvent)

	if gwDec.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Errorf("gateway decided %v, want BLOCK — the flow half of containment", gwDec.GetAction())
	}
	if epDec.GetAction() != corev1.Action_ACTION_DENY_EXEC {
		t.Errorf("endpoint decided %v, want DENY_EXEC — PREVENTED at the exec gate, not killed after",
			epDec.GetAction())
	}
	// ONE intent id, on both decisions — and context_version is already carried into the ledger entry
	// (core/audit.go), so both enactments are traceable to one intent with no hashed-column change.
	if gwDec.GetContextVersion() != intentID || epDec.GetContextVersion() != intentID {
		t.Fatalf("enactments carry context_version %q (gateway) and %q (endpoint), want both = %q — "+
			"without one id, two enactments of one containment cannot be correlated",
			gwDec.GetContextVersion(), epDec.GetContextVersion(), intentID)
	}

	// TTL EXPIRY RESTORES BOTH. A containment that cannot lapse is a permanent quarantine.
	if err := sub.Apply(signedContain(t, priv, intentID, subject, time.Now().Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	if got := decide(t, gatewayFlowPolicy, contextFor(store, subject), flowEvent); got.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Errorf("after expiry the gateway still decided %v, want ALLOW", got.GetAction())
	}
	if got := decide(t, endpointExecPolicy, contextFor(store, subject), execEvent); got.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Errorf("after expiry the endpoint still decided %v, want ALLOW", got.GetAction())
	}
}

// TestAPolicyThatIgnoresIntentsIsUnaffected pins the data-not-command property — and its honest cost: a
// deployment running a policy that never reads response_intent gets NO containment and reports nothing
// unusual.
func TestAPolicyThatIgnoresIntentsIsUnaffected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	store := intent.NewStore()
	sub := intent.NewSubscriber(pub, store)
	const subject = "sub_ignoring"
	if err := sub.Apply(signedContain(t, priv, "i-1", subject, time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	const ignoresIntents = `package openshield
import rego.v1
decision := {"action":"ALLOW","reason":"this policy does not read intents","confidence":0.5}`
	ev := &corev1.Event{EventId: "e", Kind: corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
		Subject: &corev1.Subject{PseudonymousId: subject}}
	if got := decide(t, ignoresIntents, contextFor(store, subject), ev); got.GetAction() != corev1.Action_ACTION_ALLOW {
		t.Fatalf("a policy that ignores intents decided %v — an intent must be CONTEXT, never a command",
			got.GetAction())
	}
}

func signedContain(t *testing.T, priv ed25519.PrivateKey, id, subject string, expires time.Time) []byte {
	t.Helper()
	payload, err := proto.Marshal(&corev1.ResponseIntent{
		IntentId: id, Verb: corev1.IntentVerb_INTENT_VERB_CONTAIN, Subject: subject, Version: 1,
		IssuedAt: timestamppb.New(time.Now()), ExpiresAt: timestamppb.New(expires),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := proto.Marshal(&corev1.SignedUpdate{Payload: payload, Signature: ed25519.Sign(priv, payload)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
