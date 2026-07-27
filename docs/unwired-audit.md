# Unwired-code audit

_Generated 2026-07-27 (D289). Regenerate with the sweep described at the bottom._


This is the corrected result of the sweep D288 reported as finding **zero** unwired exported
functions. That report was wrong. The sweep's interface-method exclusion used a lazy
`interface\s*\{(.*?)\}` regex with DOTALL, which on `map[string]interface{}` and multi-line
interface bodies swallowed arbitrary code and swept hundreds of ordinary function names into the
exclusion set — so almost everything was skipped and the answer came back clean. Brace-matching
named interface declarations instead gives 39 genuine interface methods and the numbers below.

**Why this matters, and what it does not mean.** A function with no caller is not automatically a
defect: read paths for a UI that has not been built, options nobody has needed yet, and test seams
are all legitimately uncalled. What IS a defect is an ACTION path — something that changes state,
enforces, publishes or approves — that nothing can reach. That is the D287 shape: a feature whose
unit tests pass and whose every path is unreachable, which from outside is indistinguishable from
one that was never built, and worse, because the tests say it works.

The 46 entries in the first table are candidates, not confirmed defects. Each needs the same
question asked: is this reachable by an operator, a loop or another component in a deployed system?

**Scope limit, stated:** this measures REFERENCES, not REACHABILITY. A function called only from
another unreachable function still counts as called here.


## Action paths with no caller — 46

_14 of these are now wired (plus XDR-6's unexported consumer seam): cases and approvals (D290), the response-intent producer (D291), the configuration write surface (D292) ENCRYPT_LOCAL recovery (D293) and coordinated-response consumption (D294). Marked inline._

The real debt. Reviewed in priority order.

| Symbol | Location | Note |
|---|---|---|
| `NewDecider` | `internal/agent/prefilter/decider.go:48` | The prefilter decider. |
| `NewDecompressGuard` | `internal/agent/sandbox/decompress.go:40` | Decompression-bomb guard (T-012). |
| `NewDepthTracker` | `internal/agent/sandbox/decompress.go:73` | Archive nesting-depth tracker. |
| `EnterArchive` | `internal/agent/sandbox/decompress.go:77` |  |
| `LeaveArchive` | `internal/agent/sandbox/decompress.go:86` |  |
| `CreateEK` | `internal/attest/ek.go:22` | TPM endorsement key. |
| `FlushEK` | `internal/attest/ek.go:38` | TPM handle cleanup. |
| `MarshalEnrollments` | `internal/attest/enrollment.go:52` | Attestation enrollment marshalling. |
| `ExtendPCR` | `internal/attest/pcr.go:44` | PCR extension. |
| `DumpArgs` | `internal/backup/backup.go:34` | Backup dump arguments (PLAT-9). |
| `Script` | `internal/backup/backup.go:81` | Backup script generation. |
| `NewWithEDM` | `internal/classify/classify.go:62` | Exact-data matching classifier variant — DLP-4. |
| `BuildEDMIndex` | `internal/classify/edm.go:137` | Builds the EDM index the above consume. |
| `NewWithRecordEDM` | `internal/classify/edm_record.go:154` | Record-level EDM classifier variant. |
| `NewWithIDM` | `internal/classify/idm.go:158` | Indexed-document matching classifier variant. |
| `SignRuleBundle` | `internal/classify/rules.go:79` | Signs a classifier rule bundle. |
| `StopMediating` | `internal/clipboard/x11/x11.go:202` | X11 clipboard mediation teardown. |
| `NewProducer` | `internal/connectors/usb/usb.go:45` | USB event producer (D1's 'one trivial USB enforcer'). |
| `Produce` | `internal/connectors/usb/usb.go:88` |  |
| `ExpirePendingApprovals` | `internal/controlplane/approvals.go:183` | **WIRED (D290).** Approvals never expire in a running deployment. 'A request left open for a week is not consent' — but nothing closes it. |
| `ReleaseLegalHold` | `internal/controlplane/cases.go:116` | **WIRED (D290).** Holds can be placed and never released. |
| `OpenCase` | `internal/controlplane/cases.go:132` | **WIRED (D290).** Operator case opening. Playbooks reach OpenCaseForIncident; a human cannot open a case. |
| `AssignCase` | `internal/controlplane/cases.go:160` | **WIRED (D290).** Case assignment. |
| `AddNote` | `internal/controlplane/cases.go:173` | **WIRED (D290).** Case notes. |
| `RequestClose` | `internal/controlplane/cases.go:189` | **WIRED (D290).** Case-close request — the first half of the four-eyes case closure. |
| `ApproveClose` | `internal/controlplane/cases.go:210` | **WIRED (D290).** Case-close approval — the second half. The whole four-eyes closure is unreachable. |
| `PublishFleetControl` | `internal/controlplane/fleetcontrol.go:75` | Superseded by PublishFleetControlSeq (D287); the wrapper is now unused. |
| `VerifySigned` | `internal/controlplane/identity.go:141` |  |
| `SetIntentBlastRadius` | `internal/controlplane/intent.go:64` | **WIRED (D291).** The blast-radius ceiling on intents. Never set, so never enforced. |
| `PublishIntents` | `internal/controlplane/intent.go:79` | **WIRED (D291).** SOAR-7's ENTIRE response-intent producer. The IdP responder IS wired and verifying — it listens for a message nothing in the product can send. |
| `RequestIntentApproval` | `internal/controlplane/intent.go:141` | **WIRED (D291).** The four-eyes request for an intent. Unreachable with its publisher. |
| `RollbackTo` | `internal/controlplane/settings.go:195` | **WIRED (D292).** Configuration rollback (D263). Revisions are recorded and cannot be rewound. |
| `CheckPurpose` | `internal/core/validate.go:117` | Purpose validation (D20). |
| `ValidateDecision` | `internal/core/validate.go:148` | Decision validation. |
| `Decrypt` | `internal/enforcers/encryptlocal/encryptlocal.go:65` | **WIRED (D293).** encryptlocal can encrypt a file. Nothing can decrypt it. |
| `NewDenyEnforcer` | `internal/enforcers/process/process.go:136` | The process DENY enforcer (HIPS-3). |
| `SetIntentResolver` | `internal/engine/engine.go:205` | **WIRED (D294).** The endpoint's intent resolver seam (XDR-6). |
| `EnforceAuditDropped` | `internal/engine/engine.go:353` |  |
| `SignUpdate` | `internal/gateway/signedupdate.go:15` |  |
| `LoadSignedFeed` | `internal/nips/signed.go:183` | Signed NIPS feed loading. |
| `VerifySignature` | `internal/notify/sign.go:42` |  |
| `NewPack` | `internal/policy/embed.go:45` |  |
| `BuildEnrollment` | `internal/posture/enroll.go:17` | Posture enrollment. |
| `IssueClientCert` | `internal/provision/provision.go:113` | Client-certificate issuance for the access proxy. |
| `InterceptionCA` | `internal/provision/provision.go:163` | The interception CA. |
| `Wrap` | `internal/transport/queue/transport.go:34` |  |


## Read paths awaiting the console — 21

Expected: PLAT-1 (the UI) is the last MVP item, and these are what it will call. They become findings if the UI ships without them.

| Symbol | Location | Note |
|---|---|---|
| `TunnelScore` | `internal/connectors/dns/dns.go:109` |  |
| `Overflow` | `internal/connectors/filewatch/filewatch.go:202` |  |
| `Refused` | `internal/connectors/smtp/listen.go:74` |  |
| `CaseNotes` | `internal/controlplane/cases.go:74` | **WIRED (D290).**  |
| `GetCase` | `internal/controlplane/cases.go:249` | **WIRED (D290).**  |
| `CurrentContextVersion` | `internal/controlplane/controlplane.go:313` |  |
| `Telemetry` | `internal/controlplane/controlplane.go:596` |  |
| `CEFListenAddr` | `internal/controlplane/external_logs.go:250` |  |
| `TicketForIncident` | `internal/controlplane/itsm.go:183` |  |
| `PlaybookRunFor` | `internal/controlplane/playbook.go:562` |  |
| `IncidentAnnotations` | `internal/controlplane/playbook_steps.go:223` |  |
| `EnactmentsForIntent` | `internal/controlplane/runner.go:151` |  |
| `Revisions` | `internal/controlplane/settings.go:147` | **WIRED (D292).**  |
| `IngestedFeeds` | `internal/controlplane/threatintel.go:110` |  |
| `AlertsForEntity` | `internal/controlplane/unified_alerts.go:110` |  |
| `Views` | `internal/controlplane/views.go:192` |  |
| `ViewsBy` | `internal/controlplane/views.go:198` |  |
| `ReadFailures` | `internal/core/killswitch.go:95` |  |
| `Expired` | `internal/core/retention.go:30` |  |
| `AppliedSequence` | `internal/intent/fleetcontrol.go:137` |  |
| `AllActions` | `internal/runner/idp.go:44` |  |


## Optional API — 9

Options and setters with a default that is currently always taken. Low concern; delete if still unused when the surface settles.

| Symbol | Location | Note |
|---|---|---|
| `WithHalfLife` | `internal/analytics/peerueba/peerueba.go:66` |  |
| `Describe` | `internal/config/config.go:360` | **WIRED (D292).**  |
| `WithInterval` | `internal/connectors/filewatch/filewatch.go:127` |  |
| `WithCap` | `internal/connectors/filewatch/filewatch.go:130` |  |
| `SetClock` | `internal/connectors/limiter/limiter.go:35` |  |
| `WithMover` | `internal/enforcers/quarantine/quarantine.go:38` |  |
| `WithMinGap` | `internal/gateway/identity/jwks.go:93` |  |
| `SetKeySource` | `internal/gateway/identity/oidc.go:96` |  |
| `Unwrap` | `internal/notify/retry.go:26` |  |


## Test seams — 8

Exist to be called by tests. Not findings.

| Symbol | Location | Note |
|---|---|---|
| `ObserveForTest` | `internal/controlplane/controlplane.go:325` |  |
| `LoadBaselinesForTest` | `internal/controlplane/controlplane.go:333` |  |
| `RecordPeerAlertForTest` | `internal/controlplane/controlplane.go:339` |  |
| `PeerRiskForTest` | `internal/controlplane/controlplane.go:345` |  |
| `RecomputeHashForTest` | `internal/core/ledger.go:440` |  |
| `ScanClaimSurface` | `internal/doccheck/doccheck.go:62` |  |
| `CheckDecisionRegister` | `internal/doccheck/doccheck.go:110` |  |
| `MappedActionsForTest` | `internal/policy/mapping.go:324` |  |


## Regenerating

The sweep is not a committed script because it is an audit, not a gate — the gate is
`TestEveryPluggableSeamHasAProductionInstaller` in `internal/fitness`, which covers the narrower
and sharper case of a pluggable seam nothing installs. Re-run this audit by collecting every
`func (…) Name(` under `internal/`, stripping comments from all non-test sources, brace-matching
`type X interface {` bodies to build the exclusion set, and counting remaining references.
