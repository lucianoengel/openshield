

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
