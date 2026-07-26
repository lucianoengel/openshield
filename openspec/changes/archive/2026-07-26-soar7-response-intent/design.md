## Context

`PublishRisk` (D91/SEC-1) is the precedent: the control plane signs a small typed message, the gateway
verifies it and puts it in a store, and the LOCAL policy decides what the number means. The server informs;
it never commands (T2/D14). ADR-12 Tier-2 asks for the same shape carrying an intent instead of a score.

Two blocked tickets consume it: XDR-6 (gateway + endpoint both enact one approved `CONTAIN`) and HIPS-3
increment 2b (the exec gate's OPA policy reading the intent as context, which D244 built the transport for).

## Goals / Non-Goals

**Goals:** a closed three-verb vocabulary; signed, versioned, TTL'd; four-eyes + blast-radius gating on
publication; consumption as verified policy context.

**Non-Goals:** enacting anything (XDR-6, HIPS-3 2b), revocation messages, N-of-M approval.

## Decisions

### D-1: A closed enum, guarded by a test like the Action set

The verbs are a proto enum with an enum-completeness test, exactly as `Action` has (D14/schema_test). The
threat is identical: an open vocabulary lets a compromised control plane express an action the endpoint
will perform. Three verbs, and a fourth is an owner decision.

### D-2: Signed, and unsigned means unpublished

Mirrors `PublishRisk`: no signer, no publication. Publishing unsigned "for now" would create a window in
which a forging publisher is indistinguishable from the control plane — and containment is a far more
attractive forgery target than a risk score.

Honest about what the signature buys: it proves ORIGIN, not authority. A validly signed intent from a
compromised control plane looks legitimate; four-eyes and the blast radius bound that damage rather than
prevent it.

### D-3: Approval is bound to the SPECIFIC intent

The four-eyes subject is the intent's id, so an approval for containing host A cannot authorize containing
host B. SOAR-3's `(subject_kind, subject_id)` shape exists for exactly this.

### D-4: The blast-radius ceiling is checked before publication, not by the consumer

A consumer cannot know how many others received the same intent. The ceiling therefore lives where the
count is known — at publication — and is a refusal, not a warning.

### D-5: Expiry is carried IN the message and evaluated by the consumer

The store returns nothing for an expired intent, so a consumer cannot act on a stale containment even if
the control plane is gone. A TTL enforced only at the publisher would leave a permanent quarantine behind
whenever the publisher dies.

## Risks / Trade-offs

- **Nothing enacts this yet.** Until XDR-6 and HIPS-3 2b land, an intent is a signal nobody acts on. Stated
  in the proposal so it is not mistaken for containment.
- **Opt-in consumption means silent gaps**: an endpoint whose policy ignores intents provides no
  containment and reports nothing unusual. Inherent to data-not-command; the alternative is the command
  channel this design exists to refuse.
- **Key compromise defeats it**, as it defeats risk publication. Bounded by four-eyes and blast radius, not
  prevented.
- **A superseding intent is the only "undo"** besides expiry. Simpler than a revocation list, at the cost
  of an operator having to publish a counter-intent rather than recall one.

## Migration Plan

Additive: a new proto message, a new NATS subject, a new store on the consuming side. Nothing changes for a
deployment that does not publish intents.
