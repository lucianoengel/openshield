# control-plane Specification

## Purpose
The server side: subscribes to agent telemetry over NATS and persists it to a fleet AGGREGATE store — distinct from and NOT carrying the agent forward-secure ledger evidentiary guarantees; only boundary-safe summaries can arrive, malformed messages are counted not dropped, and it coordinates/observes without distributing policy or controlling agents.
## Requirements
### Requirement: The control plane persists received agent telemetry
The control plane MUST subscribe to the agent telemetry subjects, decode each message, and persist
it to a fleet store keyed by agent, kind and event. A malformed message MUST be recorded and
dropped, not silently vanish and not stall the subscription.

The transport can publish telemetry and nothing consumes it; "the server coordinates" needs a
consumer. Persisting what arrives is that consumer. A malformed message that vanishes silently
would be the same missing-evidence failure the whole system guards against, so a drop is counted.

#### Scenario: Published telemetry is persisted and readable
- **WHEN** an agent publishes an Event, a ClassificationSummary and a Decision, and the control
  plane is subscribed
- **THEN** each is persisted and read back by agent and by event
- **AND** an end-to-end test over an embedded NATS asserts the round trip

#### Scenario: A malformed message is counted, not silently dropped
- **WHEN** a message that does not decode arrives
- **THEN** it is recorded as a decode failure and the subscription continues
- **AND** a test asserts the failure is observable rather than silent

### Requirement: Only boundary-safe telemetry can be received
The control plane MUST NOT be able to receive or store file content or a `LocalClassification`.
Only the `ClassificationSummary` — type, confidence, count — crosses the boundary.

The two-type split (D10) is only worth something if no path exists by which content reaches the
control plane. The transport provides no method for `LocalClassification`, so the guarantee is
structural, and the store inherits it: there is nothing to redact because content never arrives.

#### Scenario: Stored classification carries no content
- **WHEN** a classification is received and read back
- **THEN** it carries only type, confidence and count
- **AND** a test confirms no content or reversible digest is present

### Requirement: The aggregate store is not the evidentiary ledger
Documentation and any surface MUST describe the control-plane store as a fleet AGGREGATE view, not
as tamper-evident evidence. The agent's local hash-chained, forward-secure ledger is the
evidentiary record.

A compromised control plane could alter the aggregate; it has no hash chain or forward-secure
signatures. Presenting it as evidence would be exactly the overclaim the project forbids — the
integrity guarantees live at the agent (D12/D30), externally anchored (T-019), and the aggregate
must not borrow them.

#### Scenario: No surface claims the aggregate is tamper-evident
- **WHEN** the control-plane store is described
- **THEN** it is described as an aggregate view, and the evidentiary record is named as the agent
  ledger
- **AND** the agent_id is noted as self-asserted until identity (T-017) exists

### Requirement: Serving an investigation records who viewed it
When the control plane serves an investigation, it MUST record the view — viewer, what was queried,
and when — so that obtaining the evidence and leaving a record are one operation. The recorded
viewer MUST carry an identity marker and MUST be labelled unauthenticated until an authenticated
operator identity exists.

D20 requires the trail cover who VIEWED, not only who acted. The write surface that can record it is
the control plane (the CLI is a signer-less verifier, D30). Serving-and-recording atomically means a
caller cannot read the evidence without being logged. The unauthenticated label keeps a self-asserted
OS identity from being mistaken for a verified operator.

#### Scenario: A served investigation leaves a labelled view record
- **WHEN** an investigation is served through the control plane with a viewer identity
- **THEN** a view record is written carrying the viewer (labelled unauthenticated), what was queried,
  and the time, and the telemetry is returned
- **AND** a test asserts the record, the label, and that the view is readable back

#### Scenario: A bare, unlabelled viewer is refused
- **WHEN** a view is recorded with an empty viewer
- **THEN** it is rejected, so no unattributable view is silently recorded

### Requirement: The view log states its limits
The view log MUST be documented as non-evidentiary and its viewer as self-asserted — it is not the
forward-secure ledger, and the viewer is not authenticated.

A compromised control plane could alter or omit a view record, and the viewer is an OS identity, not
a verified operator. Presenting the view log as tamper-proof accountability would be the overclaim
the project forbids; the honest value is a recorded, readable trail of who looked, with its limits
named.

#### Scenario: No surface claims the view log is tamper-evident
- **WHEN** the view log is described
- **THEN** it is described as non-evidentiary with a self-asserted, unauthenticated viewer, and
  operator authentication is named as an unbuilt sibling gap

### Requirement: Signed telemetry is verified before it is persisted
The control plane MUST verify signed telemetry — the signature against the ENROLLED agent key and
the sequence for replays — before persisting it, attribute it to the VERIFIED agent, and REJECT and
count telemetry that fails (bad signature, unknown or revoked agent, replay). A sequence gap MUST be
recorded, not silently accepted.

Per-agent identity (D44) exists but was never applied to the telemetry stream, so the fleet view was
self-asserted (D41) and suppression undetectable. Verifying on ingest makes telemetry attributable
and gaps visible — the evidentiary bar telemetry needs.

#### Scenario: A validly signed message is verified and stored as attributable
- **WHEN** an enrolled agent publishes correctly signed telemetry
- **THEN** it verifies and is persisted attributed to that agent, marked verified
- **AND** a test drives it over an embedded NATS and asserts the stored, verified row

#### Scenario: An unverifiable message is rejected and counted
- **WHEN** telemetry arrives with a bad signature, from an unknown or revoked agent, or replaying a
  sequence
- **THEN** it is NOT persisted and a rejection is counted
- **AND** tests assert each case increments the rejection count and stores nothing

#### Scenario: A sequence gap is recorded
- **WHEN** a validly signed message arrives with a sequence beyond the next expected
- **THEN** the message is stored and the gap is recorded
- **AND** a test asserts the gap is observable

### Requirement: Verified and self-asserted telemetry are distinguishable
Persisted telemetry MUST record whether it was verified against an enrolled key or arrived on the
legacy unsigned path (self-asserted). The unsigned path MUST NOT be silently treated as verified.

An aggregate that cannot tell attributable telemetry from self-asserted invites the same overclaim
the project forbids — presenting unverified data as evidence. The distinction must be in the data.

#### Scenario: The stored row carries its verification status
- **WHEN** telemetry is persisted via the signed path and via the legacy unsigned path
- **THEN** the signed one is marked verified and the legacy one is marked self-asserted
- **AND** a test asserts both

### Requirement: peer alerts are a derivation, stored apart from received telemetry
The control plane MUST store a server-side peer alert in a store DISTINCT from the received-telemetry
store, because a peer alert is a control-plane DERIVATION, not an agent-attested message, and letting
a derivation sit among received rows would let it masquerade as fleet-attested evidence.

A peer alert MUST carry the pseudonymous subject, the peer-relative risk score and the context
version (D27), and MUST be recorded only after the triggering telemetry has itself verified (D50).
The peer-alert store is NOT the evidentiary ledger (D38); it is a fleet-aggregate detection surface.

#### Scenario: A peer alert is persisted separately and read back
- **WHEN** an enabled control plane records a peer alert for an outlier subject
- **THEN** the alert is written to the peer-alert store with subject, risk score and context version,
  not to the received-telemetry store
- **AND** a test reads the alert back and confirms it is absent from the telemetry rows

### Requirement: an anomalous subject raises at most one alert per rising edge
The control plane MUST throttle repeat peer alerts for a still-anomalous subject with a cooldown, so
one outlier does not emit an alert on every subsequent event while its risk stays high.

The cooldown throttles the ALERT, not the risk computation — risk is still evaluated each event; only
re-alerting within the window is suppressed. This is a rate limiter, not a change to the signal.

#### Scenario: Many events from one outlier yield one alert
- **WHEN** an outlier subject sends many events in quick succession, each above the risk threshold
- **THEN** the control plane records one peer alert for that subject within the cooldown window, not
  one per event
- **AND** a test asserts the alert count is one, not the event count

### Requirement: A restarted agent's telemetry is not rejected as a replay
The control plane MUST accept telemetry from an agent that has restarted with a persisted, forward
sequence — recording a gap if one occurred — rather than rejecting it as a replay, so a routine restart
does not silently drop an agent's telemetry.

#### Scenario: Post-restart telemetry is accepted, not replayed
- **WHEN** an agent restarts, resumes from its persisted high-water sequence, and publishes
- **THEN** VerifySigned accepts the telemetry (a gap at most), not ErrReplay
- **AND** a test drives a restart-then-publish and asserts acceptance, not replay rejection


### Requirement: The fleet aggregate has an enforced retention window
The control plane MUST purge the fleet aggregate (received telemetry and derived peer alerts) older
than a configurable window, on a periodic timer. Because the fleet aggregate is a derived detection
view and not the evidentiary ledger, its purge is a hard delete; the number of rows removed is logged.

#### Scenario: Aggregate rows past the window are deleted, recent rows kept
- **WHEN** the fleet-aggregate purge runs with a cutoff
- **THEN** telemetry and peer-alert rows older than the cutoff are deleted and rows newer than it remain

### Requirement: The operator has a read API over peer alerts and overdue agents
The control plane MUST expose operator-authenticated read endpoints for the recent peer alerts and the
overdue agents, behind the same mutual-TLS operator-role gate as the investigation view. The endpoints
MUST be read-only (hold no signer) and MUST return pseudonymous, boundary-safe fields only. A
non-operator (agent) cert MUST get 403.

#### Scenario: An operator reads peer alerts and overdue agents
- **WHEN** an operator-role client requests the alerts and overdue endpoints
- **THEN** it receives the recent peer alerts and the overdue agents as JSON

#### Scenario: A non-operator is refused
- **WHEN** an agent-role client requests those endpoints
- **THEN** it is refused with 403

### Requirement: Alerts are delivered to a configured sink, best-effort
The control plane MUST be able to deliver alerts to a configured notification sink (a webhook) in
addition to recording them, so a human is told rather than having to poll. A peer-UEBA alert MUST
trigger a notification when it is recorded. Delivery MUST be best-effort: a sink error is logged and
counted, never propagated — a down sink MUST NOT break telemetry ingest or the detection.

Delivery MUST run OFF the ingest path — a slow or retrying sink MUST NOT stall telemetry ingest; the
control plane queues the notification and delivers it asynchronously, dropping and counting a
notification only when the delivery queue is saturated. Delivery MUST retry a TRANSIENT failure (a
5xx, a 429, a timeout, a refused connection) with bounded backoff before giving up, and MUST NOT
retry a PERMANENT failure (a 4xx client error, a notification that will not serialize). Each
notification MUST carry a stable idempotency key so a receiver can dedupe a retried delivery.

#### Scenario: A webhook receives an alert as JSON
- **WHEN** a notification is delivered to a configured webhook
- **THEN** the sink receives the notification as JSON with its kind, fields, and idempotency id

#### Scenario: A slow sink does not stall ingest
- **WHEN** the configured sink blocks or retries during delivery
- **THEN** the alert is queued and ingest proceeds without waiting on delivery, and a saturated delivery queue drops and counts a notification rather than blocking

#### Scenario: A transient failure is retried and a permanent one is not
- **WHEN** a sink returns a transient error (5xx) and then a permanent error (4xx) on later notifications
- **THEN** the transient delivery is retried up to the attempt budget while the permanent one is attempted once, and in both cases the final failure is logged rather than breaking ingest

#### Scenario: A failed delivery does not break ingest
- **WHEN** a configured sink is unreachable
- **THEN** the alert is still recorded, the delivery failure is counted, and ingest is unaffected

### Requirement: The control plane publishes per-subject risk to the gateways
The control plane MUST be able to publish a per-subject risk update, so a gateway can read it for
continuous verification. It MUST publish risk when it detects an anomalous subject, best-effort — a
publish failure MUST NOT break telemetry ingest. The published risk is data the gateway interprets; the
control plane MUST NOT command the gateway to act.

#### Scenario: A detected anomaly publishes a risk update
- **WHEN** the control plane records a peer alert for a subject
- **THEN** it publishes a risk update for that subject

### Requirement: The operator can search fleet peer alerts by filter, with input bound as data
The control plane MUST let an operator search peer alerts filtered by subject, minimum risk,
and time window, returning matching alerts newest first. The filter MUST be applied as
parameterized SQL — operator-supplied values MUST be bound as query parameters, never
concatenated into the statement — so a search cannot alter or damage the store. The search
endpoint MUST sit behind the operator-role gate; a non-operator MUST be refused.

#### Scenario: A filtered search returns matching alerts and resists injection
- **WHEN** an operator searches peer alerts with subject, risk, or time filters
- **THEN** only matching alerts are returned, an injection-shaped value matches nothing and leaves the store intact, and a non-operator is refused

### Requirement: The control plane correlates alerts into incidents by a burst rule
The control plane MUST correlate peer alerts into incidents by grouping a subject's alerts
within a time window and above a risk floor, raising an incident only when the count reaches
a threshold. An incident MUST carry the subject, the alert count, the peak risk, the time span,
and the number of DISTINCT originating hosts (agents) the alerts came from, counting only real
hosts — a legacy/pre-identity alert with no host MUST NOT count as a distinct host. A subject below
the count threshold, outside the window, or below the risk floor MUST NOT raise an incident. The
correlation MUST accept an optional minimum-distinct-hosts threshold, so that an operator can select
only subjects anomalous across two or more agents — a cross-host incident — while a minimum of one
(the default) preserves the plain burst rule. The correlation MUST be parameterized (operator input
as data), its read surface MUST be operator-gated, and a malformed correlation or overdue parameter
MUST be rejected rather than silently defaulted.

#### Scenario: A burst raises an incident and a quiet subject does not
- **WHEN** the correlation rule runs over the alert aggregate
- **THEN** a subject with enough alerts in the window raises one incident with its count, peak risk, and distinct-host count, while a single-alert or out-of-window subject does not, and a non-operator is refused

#### Scenario: A cross-host threshold selects only multi-agent subjects
- **WHEN** the correlation rule runs with a minimum-distinct-hosts threshold of two
- **THEN** a subject whose qualifying alerts span two or more real agents is raised, while a subject whose alerts all came from a single agent — even with additional legacy hostless alerts — is excluded

#### Scenario: A malformed correlation or overdue parameter is refused
- **WHEN** an operator requests incidents or overdue agents with a malformed window, risk, count, or threshold parameter
- **THEN** the request is refused with 400 rather than silently widened to the default

### Requirement: The control plane manages investigation cases with four-eyes closure
The control plane MUST let an operator open a case on a subject, assign it, and add
attributed notes, with every actor recorded from a verified operator certificate. Closing a
case MUST be a four-eyes action: one operator requests closure and a DIFFERENT operator
approves it; an operator MUST NOT be able to both request and approve the same closure, and
an approval without a prior request MUST be refused. A closed case MUST record both the
requester and the approver.

#### Scenario: A single operator cannot close a case alone
- **WHEN** an operator requests a case closure and then tries to approve it
- **THEN** the self-approval is refused and the case stays open, and only a different operator's approval closes it, recording both parties

### Requirement: A correlated incident can open a pre-populated investigation case
The control plane MUST be able to open an investigation case for a correlated incident's
subject, writing an opening note that summarizes the incident (alert count, peak risk, time
span) in the same transaction, attributed to the correlation system rather than an operator.
An incident without a subject MUST NOT open a case.

#### Scenario: An incident opens a case with its summary
- **WHEN** an operator opens a case from a correlated incident
- **THEN** a case is created for the incident's subject with a system-authored note carrying the alert count and peak risk, and a subjectless incident opens no case

### Requirement: Receive-side message drops are counted, never silent
The control plane MUST install an asynchronous NATS error handler that counts and logs a
dropped message (a slow-consumer overflow above all), and MUST set explicit pending limits on
its subscriptions so an overflow is deterministic and surfaces through that handler rather
than being dropped silently. A receive-side drop MUST increment an observable counter.

#### Scenario: A slow consumer's drops are observed
- **WHEN** a subscription's pending queue overflows under load
- **THEN** the error handler fires, the drop is counted and logged, and it is never a silent loss

### Requirement: The search endpoint rejects malformed filters and bounds the result size
The alert search endpoint MUST reject a malformed filter parameter with a client error rather
than silently ignoring it, so a bad value never yields an over-broad result presented as
authoritative. It MUST cap the result-set limit at a maximum, clamping a larger request rather
than allowing an unbounded query.

#### Scenario: A malformed filter is rejected and the limit is capped
- **WHEN** a search is requested with a malformed filter param or an oversized limit
- **THEN** the malformed param yields a client error, and the oversized limit is accepted but clamped to the maximum

### Requirement: Opening a case places a legal hold on the subject's evidence
Opening an investigation case MUST place an active legal hold on the case's subject in the same
transaction as the case, so the subject's evidence cannot be purged while the investigation is
open. The hold MUST be queryable, idempotent for repeated cases on the same subject, and
releasable — with release recorded rather than deleted so the hold history stays auditable.

#### Scenario: A case holds its subject's evidence
- **WHEN** a case is opened on a subject
- **THEN** the subject is under an active legal hold, a second case on the same subject does not error, and releasing the hold ends it

### Requirement: The control plane provides a bounded event search over the fleet aggregate
The control plane MUST provide a search over the received-telemetry aggregate that filters by
originating agent, kind, event id, a time window, and an attributable-only (verified) flag,
returning matching rows newest-first. The search MUST apply every operator-supplied constraint
as parameterized SQL (input as data, never concatenated), MUST hard-cap the number of rows
returned, and MUST return row metadata only — not the stored payload. The verified-only filter
MUST exclude self-asserted (unverified) telemetry, so an investigator can restrict a case to
attributable evidence. The search's read surface MUST be operator-gated AND MUST be reachable on
the served (mutual-TLS) router — a route registered internally but not mounted on the served mux
does not satisfy this.

#### Scenario: A filtered search returns only matching, attributable rows within the cap
- **WHEN** an operator searches the aggregate by agent, kind, or time window with the verified-only flag set
- **THEN** only rows matching every constraint are returned, newest-first, with self-asserted rows excluded, bounded by the row cap, and a malformed filter parameter is refused

#### Scenario: The event-search route is reachable and role-gated on the served mux
- **WHEN** an operator certificate requests the event-search route on the served mutual-TLS router, and an agent certificate requests it
- **THEN** the operator request is routed to the search (not a 404) and the agent request is refused with 403

### Requirement: Peer alerts carry a severity and can be acknowledged
The control plane MUST derive a severity bucket for each peer alert and correlated incident from
its risk score, exposing it on the read surfaces, and MUST support filtering alerts by a minimum
severity. The control plane MUST let an operator acknowledge an alert, recording the
acknowledgement time and the acknowledging operator's VERIFIED identity (from the mutual-TLS
client certificate, never a caller-supplied name). Acknowledgement MUST be first-ack-wins — a
later acknowledgement of an already-acknowledged alert MUST NOT overwrite the original triager —
and acknowledging a non-existent alert MUST be an error, not a silent no-op. The control plane
MUST support filtering to only unacknowledged alerts, so an operator can work the actionable
queue. The acknowledgement surface MUST be operator-gated and mutating (rejecting a read method).

#### Scenario: An operator acknowledges an alert and works the unacknowledged queue
- **WHEN** an operator acknowledges an alert and then lists unacknowledged alerts at or above a severity
- **THEN** the alert is recorded acknowledged by the verified operator, a second acknowledgement does not change the triager, acknowledging a phantom id errors, and the acknowledged alert no longer appears in the unacknowledged queue while lower-severity alerts are excluded by the severity floor

### Requirement: Correlated incidents are materialized with identity and state
The control plane MUST persist a correlated incident with a stable id and a lifecycle state, with at
most one open incident per subject: re-running correlation MUST update the subject's open incident
(refreshing its counts and span) rather than duplicating it, and MUST leave an acknowledged incident
unchanged so a later burst opens a new incident. An operator MUST be able to acknowledge an incident
as a unit — first-acknowledgement-wins, a non-existent incident is an error, and a database failure
during acknowledgement MUST propagate rather than read as not-found. The incident acknowledgement
surface MUST be operator-gated and mutating.

#### Scenario: An incident is materialized once per subject and acknowledged as a unit
- **WHEN** correlation is materialized for a bursting subject, re-materialized after another alert, and then the incident is acknowledged
- **THEN** exactly one open incident exists for the subject and is refreshed (not duplicated) on re-materialization, the acknowledgement is first-wins and moves it out of the open state, and a later burst opens a new open incident while the acknowledged one remains

### Requirement: Alert delivery to multiple sinks
Alert delivery MUST support fanning out one notification to multiple sinks, so a deployer can page
one system and archive to another. A fanout delivery MUST attempt every configured sink even when an
earlier sink fails, so one broken sink cannot suppress delivery to the healthy ones. The fanout MUST
report an aggregate failure when any sink fails so the caller can log it, and MUST classify the
aggregate as permanent only when every failing sink failed permanently. Retry composes beneath the
fanout (per-sink), so a retry re-attempts only the failed sink and never re-pages a succeeded one.

#### Scenario: One failing sink does not suppress a healthy sink
- **WHEN** a notification is delivered to a fanout of two sinks and the first sink errors
- **THEN** the second sink still receives the notification and the fanout returns an aggregate error naming the failure

### Requirement: Authenticated webhook body
A webhook sink MUST optionally authenticate its payload so a receiver can verify an alert genuinely
came from this control plane and was not tampered with. When a signing secret is configured, the
webhook MUST send an `X-Openshield-Signature: sha256=<hex>` header whose value is the HMAC-SHA256 of
the exact request body, and verification MUST use a constant-time comparison. When no secret is
configured, the webhook MUST send no signature header and the body MUST be byte-for-byte unchanged.

#### Scenario: A signed body verifies and a tampered body is rejected
- **WHEN** a webhook is configured with a secret and posts a notification
- **THEN** the request carries an `X-Openshield-Signature` header over the body that verifies with the same secret, while a tampered body or a wrong secret fails verification

### Requirement: Peer-UEBA baselines survive a restart
The control plane MUST persist the peer-UEBA baseline and reload it when peer-UEBA is enabled, so a
restart or deploy does not cold-start analytics and blind the fleet to peer anomalies for a decay
window. Persistence MUST be best-effort: a failure to load a persisted baseline MUST log and start
cold rather than block enabling detection, and persistence MUST NOT break or stall ingest.
Re-persisting MUST be idempotent per subject.

#### Scenario: A subject's baseline survives a simulated restart
- **WHEN** subjects are observed and baselines are persisted, then a fresh control-plane instance enables peer-UEBA
- **THEN** the fresh instance loads the persisted baseline so a subject's peer risk is preserved, while an instance with no persisted baseline starts cold with no baseline
