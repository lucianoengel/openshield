## ADDED Requirements

### Requirement: Cloud-service (CASB) classification of a network flow

The system SHALL classify a network flow against an operator-configured cloud-service catalog, deriving
the cloud service the flow addresses (by destination host), the service's category, whether the service
is operator-SANCTIONED, and whether the flow is an UPLOAD (a mutating request method). This
classification MUST be a pure, content-free derivation of the flow METADATA (host and method) — it MUST
NOT open or inspect the body. A flow to a host in no catalogued service MUST yield no cloud match, and a
flow with no configured catalog MUST leave the pipeline unchanged (the feature is inert until
configured). A malformed catalog entry MUST fail to load with an error; the parser MUST reject a
degenerately broad host suffix that would match unrelated traffic.

#### Scenario: An upload to a catalogued cloud service is classified
- **WHEN** a flow's destination host matches a catalogued service and the request method is mutating (an upload)
- **THEN** the flow is classified with that service, its category, its sanctioned status, and upload = true

#### Scenario: A download to a cloud service is not an upload
- **WHEN** a flow's destination host matches a catalogued service but the request method is non-mutating (a GET)
- **THEN** the flow is classified with the service but upload = false

#### Scenario: A non-cloud flow yields no cloud match
- **WHEN** a flow's destination host is in no catalogued service
- **THEN** no cloud classification is produced for the flow

#### Scenario: A malformed catalog fails to load
- **WHEN** the cloud-service catalog has an unparseable entry or a degenerately broad host suffix
- **THEN** loading the catalog returns an error and the offending entry is not silently dropped

### Requirement: Policy sees the cloud channel of a network flow

The system SHALL expose a network flow's cloud classification (service, category, sanctioned, upload) to
the policy so a rule can gate sensitive content bound for a cloud sink — in particular, block sensitive
content uploaded to an UNSANCTIONED service while allowing the same content to a SANCTIONED one. The
cloud classification MUST be content-free; the sensitivity of the content comes from the existing body
classification, and the policy — not the engine — combines the two. The cloud engine MUST NOT block on
its own, and its absence MUST NOT deny a flow.

#### Scenario: A policy blocks a sensitive upload to an unsanctioned cloud service
- **WHEN** a policy that blocks on sensitive content plus an unsanctioned cloud upload evaluates a flow whose body carries sensitive content and whose destination is an unsanctioned catalogued service
- **THEN** the decision is to block the flow

#### Scenario: The same content to a sanctioned service is allowed
- **WHEN** the same sensitive-content upload targets a SANCTIONED catalogued service
- **THEN** the flow is not blocked by the unsanctioned-upload rule

#### Scenario: Clean content to an unsanctioned service is not blocked by the rule
- **WHEN** a flow with no sensitive content uploads to an unsanctioned cloud service
- **THEN** the sensitive-content-plus-unsanctioned-upload rule does not fire (both conditions are required)

### Requirement: The cloud-service catalog hot-reloads without a restart

The system SHALL reload the cloud-service catalog when its file changes, so a change to a service's
sanctioned status or host set takes effect without a restart, swapping the running catalog atomically
(in-flight flows keep the catalog they read). A changed-but-malformed catalog SHALL be reported and the
current catalog KEPT — a bad edit MUST NOT disarm the running classifier. The initial baseline SHALL be
established synchronously when the watcher is constructed, so a flow classified immediately after startup
cannot race an unread catalog.

#### Scenario: A sanctioned-status change takes effect after an edit
- **WHEN** the catalog file is edited to mark a previously-unsanctioned service as sanctioned and the reload interval elapses
- **THEN** a subsequent sensitive upload to that service is no longer blocked, with no restart

#### Scenario: A malformed edit is served-stale
- **WHEN** the catalog file is changed to a version that fails to parse
- **THEN** the error is reported and the previously-loaded catalog keeps serving
