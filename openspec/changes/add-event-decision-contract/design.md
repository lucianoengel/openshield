## Context

Nothing exists yet. `internal/core` holds a `doc.go` stating the pipeline is fixed; there are no
types, no producers, no consumers. That is the ideal moment to fix contracts, and the reason
this is the first change rather than something more visibly productive.

Three constraints shape every decision below:

- **Structural over procedural.** Several project invariants (closed action set, no content on
  the wire, enforcer isolation) are only real if the type system or CI makes violations
  impossible. Expressed as convention they decay, and this project has already watched
  documentation drift twice in a week.
- **Reviewability.** The maintainer directs and reviews but does not write code
  ([`CONTRIBUTING.md`](../../../CONTRIBUTING.md)). Designs whose correctness depends on
  line-level scrutiny are the wrong shape here; designs enforced by a failing build are right.
- **Provisionality where evidence is missing.** T-005 has not yet run, so how filesystem events
  identify their subject is genuinely unknown.

## Goals / Non-Goals

**Goals:**
- Define `Event`, `LocalClassification`, `ClassificationSummary` and `Decision` in protobuf.
- Make the closed action set, the content-free wire form, and enforcer isolation enforceable by
  the compiler or CI rather than by review.
- Generate Go types into `internal/core` and commit them, so `go build` works without protoc.
- Leave a clean seam for the path-vs-handle question T-005 will answer.

**Non-Goals:**
- Transport, authentication, agent identity (T-017).
- The audit record format and its hash chain (T-009).
- Policy language and evaluation semantics (T-008).
- Any enforcement behaviour (Phase 2).
- Discovery/catalog and lineage/graph shapes — review finding A2 established these do not fit
  the event-stream model, and speculating now would bake in a guess.

## Decisions

### Protobuf as the definition, Go generated from it

**Chosen:** `.proto` files under `proto/openshield/v1/`, generated Go committed to
`internal/core/corev1/`.

**Why not hand-written Go structs?** The project is single-language today (D8), which weakens
the usual cross-language argument. Protobuf still wins on three counts specific to this system:
an explicit wire format for an audit trail that must be replayable years later; enum semantics
that make the closed action set (D14) a property of the schema rather than of Go's weak enum
convention; and field-number-based evolution rules that make "what changed in the contract"
reviewable in a diff — which matters when the maintainer's review is at design level.

**Cost, stated plainly:** a protoc toolchain dependency and generated code in the tree.
Mitigated by committing generated output and adding a CI check that it matches the sources.

### Two classification types, not one type with redaction

**Chosen:** `LocalClassification` (host-only) and `ClassificationSummary` (wire) as separate
messages, with no conversion that carries content across.

**Why not one type plus a `Redact()` step?** Because redaction is a runtime behaviour, and
runtime behaviours get skipped — a new code path, a debug logger, a retry that serializes the
pre-redaction value. Two types turn that into a compile error. The transport interface accepts
only `ClassificationSummary`, so sending the local form is not a bug to catch in review but a
program that does not build.

The cost is duplication between two similar messages. Accepted: the duplication is visible and
static, the failure mode it prevents is invisible and dynamic.

### Closed enum for actions, with no sibling parameter fields

**Chosen:** `Action` is a protobuf enum; `Decision` has no field capable of carrying a URL,
path, host or command.

The threat is specific: a compromised control plane distributing a policy whose action is
"upload file to URL". With an open action surface that instruction is expressible and, at the
enforcement point, indistinguishable from legitimate telemetry. A closed enum makes it
unexpressible. A schema test enumerates the permitted members, so adding an action requires
editing the test — a deliberate speed bump on the system's most security-sensitive field.

**Rejected:** an `Action` message with a `params map<string,string>`, which would have made
future enforcers easier to write and this guarantee impossible to keep.

### Enforcer isolation proven by a non-compiling test package

**Chosen:** a `//go:build ignore`-style negative test — a package that references a
Classification from an enforcer context, with CI asserting it **fails** to compile.

**Why not a comment or a lint rule?** Because the requirement is "an enforcer cannot see
classifier internals", and the only faithful test of *cannot* is a compilation that fails.
A lint rule tests "does not today".

**Risk:** negative compile tests are brittle — they can pass for the wrong reason, e.g. a typo
making compilation fail unrelatedly. Mitigated by asserting on the specific compiler error
substring, not merely on non-zero exit.

### Path vs handle: a oneof, deliberately provisional

**Chosen:** the filesystem subject is a `oneof { string resolved_path; bytes file_handle; }`
plus a discriminator, so both forms are expressible before T-005 tells us which we get.

Unprivileged fanotify reports file handles rather than descriptors, and resolving one to a path
may require `CAP_DAC_READ_SEARCH`. Committing to `string path` now risks a schema change after
consumers exist; a `oneof` costs one level of indirection and buys the option.

**This is the change's weakest point and is marked as such.** If T-005 shows only one form ever
occurs, the `oneof` should collapse — and that revision must happen before T-007/T-008/T-009
build on it.

### Generated code is committed

**Chosen:** commit `*.pb.go`; CI verifies regeneration produces no diff.

Contributors and CI can build with a plain Go toolchain. The alternative — generating at build
time — adds a protoc dependency to every consumer for no benefit at this size.

## Risks / Trade-offs

- **The schema is being fixed before the producer is understood (T-005).** → Explicit escape
  hatch: this change is revised, not patched around, if T-005 contradicts it. Recorded in the
  proposal, the spec and the ticket. The `oneof` limits the blast radius.
- **Two classification types will drift.** → A shared test fixture set exercises both; the wire
  type's field list is asserted exactly, so adding a field there fails CI.
- **A negative compile test can pass spuriously.** → Assert on the expected error text.
- **Protobuf enums default to zero.** `ACTION_UNSPECIFIED = 0` means a zero-valued Decision is
  syntactically valid. → Validation rejects `ACTION_UNSPECIFIED` on any Decision leaving the
  policy engine; the spec requires unknown actions be rejected rather than defaulted.
- **Committed generated code invites hand-editing.** → CI regeneration check catches it.
- **Overconfidence in structural enforcement.** These checks constrain the *shape* of data, not
  its truth. Nothing here prevents a classifier putting a customer name into a field legitimately
  typed as a string. Structural guarantees are necessary, not sufficient — worth stating because
  the temptation is to treat a green CI as proof of privacy.

## Migration Plan

No migration; nothing consumes these types. Ordering: proto sources → generate → validation →
schema tests → negative compile test → CI wiring. Rollback is deleting the change.

## Open Questions

1. **Path vs handle** — T-005 decides. Blocks collapsing the `oneof`.
2. **Does `Event` need a device/mount identifier?** Probably, for handle resolution, but T-005
   determines whether it is separate or embedded in the handle.
3. **Should `ClassificationSummary` carry a coarse severity, or only a detector type?** Deferred
   to T-008, when the policy engine shows what it actually needs to consume.
4. **Sequence numbers per agent or per connector?** Per agent is simpler; per connector detects
   gaps more precisely. Deferring to T-022, which will own event ingestion.
