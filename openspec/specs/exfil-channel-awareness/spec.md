

## Purpose

Where data is GOING, derived from metadata alone: a file path's channel (local, removable, cloud-sync),
the clipboard and print as first-class channels, and a network flow's cloud service from an operator
catalog including whether that service is SANCTIONED and whether the flow is an upload. The engine never
blocks on this; it hands the channel to the policy, which combines it with the content classification
the worker produced.

## Requirements

### Requirement: The clipboard is a first-class exfiltration channel

The exfil channel model SHALL include a clipboard channel alongside local, removable media and cloud sync,
and a clipboard event SHALL be tagged with it when policy input is built. A channel-aware policy SHALL
therefore be able to treat a sensitive copy-paste the same way it treats a sensitive write to a cloud-sync
folder, without knowing anything clipboard-specific.

Unlike the other channels, this one is NOT derived from a filesystem path — a clipboard copy has no path —
so it SHALL be assigned from the event kind rather than by path classification.

#### Scenario: A clipboard event reaches policy tagged as the clipboard channel
- **WHEN** policy input is built for a clipboard-copy event
- **THEN** its exfil channel is the clipboard channel
- **AND** a path-derived channel is not inferred for it

### Requirement: The configured cloud-service catalog reaches the running gateway

The gateway SHALL load its cloud-service catalog from the configured path at startup and install it as
the catalog the policy input consults, so that a catalogued destination is classified by the RUNNING
process and not merely by a library the process could fail to call. A catalog that is configured but
malformed SHALL abort startup rather than leave the engine silently inert.

When a reload interval is configured, an edit to the catalog SHALL take effect without a restart, and a
malformed EDIT SHALL be reported while the CURRENT catalog is kept — a typo must never disarm cloud-upload
control across a fleet.

#### Scenario: A sensitive upload to a catalogued unsanctioned service is prevented by the running gateway
- **WHEN** a catalog is configured and a sensitive body is uploaded through the gateway to an unsanctioned catalogued destination
- **THEN** the request is refused and the destination receives nothing

#### Scenario: The same upload to a sanctioned service is forwarded
- **WHEN** the same sensitive body is uploaded to a SANCTIONED catalogued destination
- **THEN** the request is forwarded and the destination receives it

#### Scenario: Withdrawing sanction takes effect without a restart
- **WHEN** the catalog is edited so a previously sanctioned service is no longer sanctioned, and the reload interval elapses
- **THEN** a subsequent sensitive upload to that destination is refused

#### Scenario: A malformed edit leaves the running catalog in force
- **WHEN** the catalog file is subsequently edited into an unparseable state
- **THEN** the failure is reported and the previously loaded catalog continues to classify flows

### Requirement: Exfil-channel classification of a file path

The system SHALL classify the exfiltration channel a file path is on — removable media (under a
configured mount root), a cloud-sync folder (identified by a folder-name component), or local as the
explicit default — from the path alone, without opening the file or performing a blocking filesystem
lookup in the decision path. Every classified path MUST yield a concrete channel, never an absent value.

#### Scenario: A removable-media path is classified

- **WHEN** a file path is under a configured removable mount root
- **THEN** it is classified as removable media

#### Scenario: A cloud-sync folder path is classified

- **WHEN** a file path contains a configured cloud-sync folder-name component
- **THEN** it is classified as cloud-sync, regardless of the home/prefix

#### Scenario: An ordinary path is local

- **WHEN** a file path matches no removable root and no cloud-sync folder
- **THEN** it is classified as local

<!-- restored from 2026-07-22-dlp2-exfil-channel-awareness -->

### Requirement: Policy sees the exfil channel of a file event

The system SHALL expose the exfil channel of a filesystem event to the policy so a rule can escalate a
sensitive write to an exfiltration channel differently from a local write. The channel MUST be a
content-free derivation of the event's path.

#### Scenario: A policy escalates a sensitive write to an exfil channel

- **WHEN** a policy that escalates on sensitive content plus a non-local exfil channel evaluates a
  sensitive file written to a cloud-sync or removable path
- **THEN** the decision escalates, while the same sensitive content written to a local path does not

<!-- restored from 2026-07-22-dlp2-exfil-channel-awareness -->

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

<!-- restored from 2026-07-23-dlp2-content-aware-casb -->

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

<!-- restored from 2026-07-23-dlp2-content-aware-casb -->

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

<!-- restored from 2026-07-23-dlp2-content-aware-casb -->
