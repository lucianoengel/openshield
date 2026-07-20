## Why

Everything in OpenShield is downstream of two contracts: the `Event` that enters the pipeline
and the `Decision` that leaves it. They are the hardest things in the system to change later —
the classifier, policy engine, audit ledger and every future connector and enforcer all key off
them. Getting them wrong is expensive in a way that getting the classifier wrong is not.

They are being specified now, before any pipeline code exists, because several architectural
invariants can only be guaranteed *structurally*. A closed action set is a property of the type,
not of a code review. "No content leaves the endpoint" is a property of what fields exist, not
of developer discipline. If these are conventions rather than types, they rot.

Implements ticket T-003 ([`docs/plan-phase1.md`](../../../docs/plan-phase1.md)).

## What Changes

- New protobuf definitions for the pipeline's core messages: `Event`, `Classification`,
  `Decision`, and the enums they depend on.
- Generated Go types under `internal/core`, with `protoc` wired into the build.
- A **closed, typed `Action` enum** — `BLOCK`, `ALERT`, `QUARANTINE_LOCAL`, `ENCRYPT_LOCAL`
  (D14). Deliberately not an open string or a URL-bearing struct.
- `Decision` carries a **confidence score, not a boolean verdict** (D4).
- `Classification` is split into two distinct messages: a **local** form the endpoint uses
  internally, and a **wire** form carrying only type + confidence + count, with no field capable
  of holding content or a reversible hash of low-entropy PII (D10).
- `Event` carries a **stable pseudonymous subject ID** (D23) and a **purpose tag** (D20).
- A compile-time test proving the enforcer interface cannot reach classifier internals
  (CrowdSec separation).

**Not breaking** — there is nothing to break yet. That is the point of doing it now.

## Capabilities

### New Capabilities
- `event-contract`: the `Event` message — what a producer emits, its identity, subject,
  purpose and provenance fields, and what it is forbidden from carrying.
- `decision-contract`: the `Decision` message and the closed `Action` enum — what the policy
  engine emits and what an enforcer is permitted to see.
- `classification-contract`: the split between endpoint-local classification output and the
  wire form that may leave the host.

### Modified Capabilities
None. `openspec/specs/` is empty; this change establishes the first specs.

## Impact

- **Code:** `internal/core` gains generated types and the interfaces that constrain them.
  `cmd/` unaffected. No connector, classifier or enforcer implementations exist yet, so there
  are no downstream consumers to migrate.
- **Build:** adds a `protoc` + `protoc-gen-go` dependency and a generation step. Generated code
  is committed so a plain `go build` works without protoc installed.
- **CI:** adds two checks — generated code is up to date with the `.proto` sources, and the
  enforcer-isolation compile-time test.
- **Downstream tickets:** T-007, T-008, T-009 and T-022 all build directly on these types.

## What this change does NOT do

- **Does not enforce anything.** Phase 1 is observe-and-audit only (D1). `Action` values are
  defined and recorded; nothing acts on them until Phase 2.
- **Does not claim the schema is final.** T-005 (fanotify observe spike) has not yet
  characterised whether events arrive with resolvable paths or only kernel file handles. If it
  contradicts this schema, **this change is revised immediately** — before T-007/T-008/T-009
  build on it. That escape hatch is deliberate and is recorded in the ticket.
- **Does not model Data Discovery or Lineage.** Review finding A2 established that a catalog
  and a graph do not fit the event-stream shape. Forcing them in now would be speculative; the
  peer-UEBA paper design (T-004) is the test of whether the pipeline stretches that far.
- **Does not define the audit record format.** That is T-009, which consumes `Decision` but adds
  its own hash-chain and forward-integrity fields.
- **Does not address transport, authentication or agent identity.** That is T-017.
