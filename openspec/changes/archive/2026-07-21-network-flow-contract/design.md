## Context

`Event` carries `oneof target { FilesystemSubject filesystem = 9; UsbSubject usb =
10 }` and metadata (subject, purpose, kind) — never content (D10). `Action` is a
closed enum (D14). The `core.Dispatcher` runs Event → stages → Decision →
OnOutcome, data-plane-agnostic in principle. `core.TargetedEnforcer.EnforceTarget
(ctx, dec, target string)` carries a file path today. The question this settles:
what does the NETWORK domain add to the core, and does the dispatcher change?

## Goals / Non-Goals

**Goals:**
- Represent a network flow / L7 request as an Event (metadata only).
- Represent a network verdict (redirect) in the closed action set.
- PROVE a network Event flows through the UNCHANGED dispatcher and is decided +
  audited, with the verdict carried out by the existing enforcer interface.

**Non-Goals:**
- The proxy data plane (TLS interception, flow table, classifier, flow-enforcer
  implementation, telemetry projection) — this is the contract + fitness proof.
- New enforcer interfaces — the flow enforcer reuses `TargetedEnforcer`.
- Reset/drop as verdicts — they are enforcement modes.

## Decisions

**NetworkSubject is a new `oneof target` variant — the USB precedent.** USB added a
`UsbSubject` variant; network adds `NetworkSubject` the same way. It carries
METADATA ONLY: `flow_id` (opaque handle into the gateway's live flow table — the
network analogue of a file path, what an enforcer acts on), the 5-tuple, and L7
metadata (sni_host, http_method, http_path, direction). The BODY is never in the
Event — it is classified in the gateway process and only type+count+confidence
crosses to telemetry, exactly as file content stays in the worker (D10/D29).

**`flow_id` reuses the enforce target — no new enforcer interface.** A file
enforcer resolves `target` to a path; a flow enforcer resolves `target = flow_id`
to a live connection in its flow table and drops/resets/redirects it. Both are
opaque domain references interpreted by whichever enforcer a NODE registers (the
gateway registers flow enforcers; the endpoint registers file enforcers), so
`core.TargetedEnforcer` is unchanged. Each node's own Process/enforce reads its
domain's target (the engine reads `GetFilesystem().GetResolvedPath()`; the proxy
would read `GetNetwork().GetFlowId()`) — node code, outside core.

**One new action: REDIRECT. Block-vs-reset is a mode, not a verdict.** The policy
decides deny (BLOCK, reused) or send-to-coaching (REDIRECT, new). Whether a denied
TCP flow is dropped silently or RST is an enforcer/config choice, not something a
policy author expresses — so it does NOT get an action, keeping the vocabulary
small (D14). REDIRECT is added to the enum AND to `validate.go`'s allowed set (or
a REDIRECT decision fails validation).

**Fitness proof mirrors peer-UEBA (D53).** A test builds a network Event
(HTTP_REQUEST + NetworkSubject), runs it through the EXISTING `core.NewDispatcher`
with a fake network-classify stage and a policy stage reading host/path and
emitting REDIRECT/BLOCK, asserts the Decision and the audited outcome, and a fake
flow enforcer (implementing `TargetedEnforcer`) carries out the verdict via
`target = flow_id`. The Dispatcher, State, Stage, Registry, Enforcer interface,
OnOutcome and ledger are untouched — the proof that the pipeline is data-plane-
agnostic, not just claimed to be.

## Risks / Trade-offs

- **`flow_id`/host/path metadata is sensitive.** URLs and hosts reveal browsing;
  they are the DPIA scope of the gateway (employee monitoring of egress). The
  contract carries them because the policy needs them to decide; the TELEMETRY
  projection (what crosses to the server) is a separate, boundary-safe step
  designed with the proxy, not here. Stated, not hidden.
- **Reusing `target string` across domains is loose.** A path and a flow_id are
  different things in one field. Mitigated by each node registering only its
  domain's enforcers, so the string is always interpreted in one domain. A typed
  target is a possible future refinement, noted.
- **This is a contract, not a capability.** It proves fitness and unblocks N1; it
  delivers no network enforcement on its own. The proposal states plainly what is
  NOT built so "network contract added" is not misread as "network DLP works".
