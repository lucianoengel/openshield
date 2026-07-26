## Context

Shipped at D253 (`fb6294c`). D244 built the parser-free IPC bridge from the privileged exec gate to the
unprivileged engine; D252 built the signed intent seam. This joined them.

## Goals / Non-Goals

**Goal:** make the spec describe the shipped behaviour.
**Non-Goals:** any code change; the gateway half (XDR-6/D254).

## Decisions

### D-1: The intent lives on `core.Context`, as a closed enum

`core.Context` is the closed typed enrichment set whose docstring already requires a deliberate schema
change to extend — the right home, and the reason the field is `corev1.IntentVerb` rather than a string.
An open map or a free-text field would be D14's threat arriving by a different door.

`HasResponseIntent` mirrors `HasRiskScore`: "not computed" and "computed, and it says nothing" must stay
distinguishable, or absence reads as safety.

### D-2: Resolution rides the existing `ResolveContext` hook

`Dispatcher.ResolveContext` is the one small core seam peer-UEBA established (D26). Reusing it meant no new
core mechanism for this capability — the fitness property the frozen core exists to preserve.

### D-3: The consumer package is neutral

The intent store/subscriber lives in `internal/intent`, not `internal/gateway`, because both the network
gateway and the endpoint engine consume intents and the endpoint must never import the network layer.

## Risks / Trade-offs

- **Spec-after-code is a weaker guarantee than spec-first**, and this change is exactly that. The delta was
  written against the shipped code and its VM-proven test rather than the reverse, so it inherits whatever
  the implementation assumed. It is recorded as retroactive so a reader does not mistake it for a design
  document that preceded the work.
- The data-not-command property's coverage gap (a policy that ignores intents) is inherent, not fixable
  here.

## Migration Plan

None — documentation of shipped behaviour.
