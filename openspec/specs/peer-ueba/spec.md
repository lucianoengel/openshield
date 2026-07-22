# peer-ueba Specification

## Purpose
Peer-baseline UEBA — the real architecture test (D26): a stateful, cross-entity capability that computes a subjects risk relative to its peers and feeds it to policy. Building it confirmed D26 in code — it needed exactly ONE small, identifiable core change (a Dispatcher.ResolveContext hook), no more; the zero-core-change claim is false, the small-change claim true.
## Requirements
### Requirement: A new-shape capability is absorbed with one small, identifiable core change
Building peer-baseline UEBA MUST require exactly one small, identifiable core change — a Context
resolver hook on the dispatcher — and no more. With the hook unset, pipeline behaviour MUST be
unchanged (Context nil, observe-only).

D26's real test is whether the architecture absorbs a genuinely new-shape capability (stateful,
cross-entity) as a plugin or forces a sprawling core change. The honest answer, found in code: it
needs ONE named hook. That validates the small-change claim and disproves the zero-change one — and
pretending none was needed would be the overclaim the fitness test exists to expose.

#### Scenario: The core change is exactly the resolver hook
- **WHEN** peer-UEBA is built
- **THEN** the only core change is a `ResolveContext` hook on the dispatcher; the analyzer itself is
  entirely outside core
- **AND** the capability-boundary check still passes (core does not import the analyzer), and a nil
  resolver leaves behaviour unchanged

### Requirement: Peer-UEBA computes a cross-entity risk and feeds a Decision
The analyzer MUST compute a subject's risk RELATIVE to its peers (stateful, cross-entity) and
produce a Context the policy consults, so the peer signal can influence a Decision end to end.

Peer-baseline UEBA is the new shape precisely because it is stateful and cross-entity — a subject is
risky relative to OTHERS, not by a per-event rule. Proving it feeds a Decision through the Context
seam is proving the seam works for the shape it was designed for.

#### Scenario: An anomalous subject's peer risk escalates the Decision
- **WHEN** one subject's activity is far above its peers and a policy consults the peer risk score
- **THEN** its Context carries a high risk score and the policy escalates the Decision on that
  signal, even absent a PII hit
- **AND** a test drives the analyzer, the resolver, and a peer-aware policy and asserts the escalation

#### Scenario: Off by default leaves observe-only unchanged
- **WHEN** no resolver is configured
- **THEN** the Context is nil and behaviour is exactly Phase-1 observe-only
- **AND** a test asserts a nil resolver changes nothing

### Requirement: peer-UEBA runs server-side over the verified fleet stream
The analyzer MUST be able to consume the control plane's VERIFIED telemetry stream, accumulating a
cross-fleet peer baseline from each verified event's pseudonymous subject, because a single endpoint
has no peers and the capability can only function where the whole fleet converges.

Only VERIFIED telemetry may move a baseline — an unverified or rejected message is not evidence
(D50) and MUST NOT influence any subject's peer-relative risk. The subject observed is the
pseudonymous id (D23), never a re-identified user.

#### Scenario: A verified outlier raises a peer alert; a typical subject does not
- **WHEN** the fleet analyzer is enabled and an outlier subject's activity crosses the peer-risk
  threshold while a typical subject stays near the peer mean
- **THEN** a peer alert is recorded for the outlier subject carrying its risk score and context
  version, and no alert is recorded for the typical subject
- **AND** a test asserts the discrimination end to end over the telemetry path

#### Scenario: Unverified telemetry does not move a baseline
- **WHEN** a message fails verification (bad signature, unknown/revoked agent, or replay)
- **THEN** it is rejected and the subject's peer baseline is unchanged
- **AND** a test asserts a rejected message contributes nothing to peer risk

### Requirement: peer-UEBA server-side detection never controls agents
The server-side integration MUST only produce investigations at the control plane and MUST NOT feed
risk back to agents or alter agent behaviour, preserving the observe-not-control boundary (D14).

The endpoint policy-Context seam (the `Dispatcher.ResolveContext` hook, D53) remains the core
integration point, but the running system uses peer-UEBA as a server-side detector; the two seams
are distinct and the fleet one does not close a control loop.

#### Scenario: A peer alert produces no agent-directed action
- **WHEN** the analyzer records a peer alert for a subject
- **THEN** the control plane persists a server-side detection only
- **AND** no message is sent to any agent and no agent behaviour changes as a result

### Requirement: server-side peer analysis is off by default
The fleet analyzer MUST be disabled unless explicitly enabled by operator configuration, so a
control plane does not silently profile a fleet without the consent/DPIA decision (D23).

#### Scenario: Disabled by default records nothing
- **WHEN** the control plane runs without peer-UEBA explicitly enabled
- **THEN** no subject is observed and no peer alert is ever recorded
- **AND** a test asserts the default control plane produces no peer alerts

### Requirement: The peer baseline excludes the subject under test
Peer-relative risk MUST compute the peer baseline from the OTHER subjects' activity, excluding the
subject being scored, so a subject cannot contaminate the baseline it is judged against.

Under leave-one-out an outlier scores MORE clearly anomalous than when its own activity is folded into
the mean/stddev. A population too small to have peers after excluding the subject still returns no
Context (no risk emitted on noise), preserving the small-population guard.

#### Scenario: An outlier scores higher with leave-one-out than self-included
- **WHEN** a subject far above its peers is scored with the peer baseline excluding it
- **THEN** its risk is at least as high as, and for a strong outlier strictly higher than, a baseline
  that includes its own activity
- **AND** a test asserts the leave-one-out score exceeds the self-included score for a strong outlier

### Requirement: Old activity decays so a steady subject does not drift into anomaly
Accumulated activity MUST decay over time, so a subject with a steady rate of activity reaches a
bounded level near its peers rather than climbing monotonically into a false anomaly.

Decay is deterministic given the time source (an injected clock, not wall-clock inside the analyzer),
so the behavior is testable. A genuine burst still rises above the decayed peer level; only steady
accumulation is bounded.

#### Scenario: A steady-but-busy subject stays within its peers over time
- **WHEN** a subject sustains a steady activity rate comparable to a busy peer over a long period
- **THEN** its decayed level stays bounded near its peers and it is not flagged as an outlier
- **AND** a test shows the same subject WOULD drift into outlier under a non-decaying cumulative count

#### Scenario: The public Analyzer API is unchanged
- **WHEN** the hardened analyzer is used through Observe / ContextFor / Resolver
- **THEN** the signatures and the emitted context_version (D53) are unchanged and downstream wiring
  (the dispatcher hook, the fleet consumer) still compiles and runs
- **AND** the existing peer-UEBA tests continue to pass


### Requirement: The context version does not collide across restarts
The peer-UEBA context version MUST be monotonic and non-colliding across process restarts, so a
Decision's recorded context version unambiguously identifies which analytics snapshot applied.
Each startup MUST reserve a monotonic version range from durable storage so its versions sit in
a distinct range from any prior run.

#### Scenario: Two runs produce disjoint context versions
- **WHEN** peer-UEBA is enabled on two successive runs sharing the store
- **THEN** the two runs' context versions never coincide for the same activity

### Requirement: The analyzer can snapshot and restore its baseline exactly
The peer-UEBA analyzer MUST expose a serializable snapshot of its per-subject baseline and MUST be
constructible from such a snapshot. Because activity decay is computed forward from each subject's
last-update time, a restored analyzer MUST compute the same peer-relative risk for a subject as the
original analyzer would at the same evaluation time — restoring is exact, not approximate.

#### Scenario: A restored analyzer reproduces the original risk
- **WHEN** subjects are observed, the analyzer is snapshotted, and a new analyzer is constructed from that snapshot
- **THEN** the new analyzer computes the same peer-relative risk for a subject as the original, and an empty snapshot yields a cold analyzer with no baseline
