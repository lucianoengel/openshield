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

Classified 2026-07-27 (D295) — each entry checked against whether the CAPABILITY is reachable by
another path, not merely whether this symbol is called. **The classification changed the picture: most
of these are not gaps.**

| Verdict | Count | Meaning |
|---|---|---|
| **WIRED** | 14 | fixed in D290–D294 |
| **SUPERSEDED / UNUSED SIBLING** | 16 | the capability ships through another call; this symbol is unused API |
| **NOT BUILT / PARTIAL** | 12 | the feature was never finished — debt, but not a regression |
| **DUPLICATE** | 4 | a second implementation of a property something else already enforces |
| **DEAD** | 1 | no caller and no test |
| **TOOLING GAP** | 1 | the product verifies an artifact it gives no way to produce |

**I nearly wired something already wired.** `NewWithEDM` and its siblings looked like exact-data matching
being unreachable; the worker in fact loads all three index kinds through `AddEDM`/`AddRecordEDM`/`AddIDM`,
driven by settings that are read. Checking before building is the whole point of this pass.

All three follow-ups are done (D297). They were: **`SignRuleBundle`** (the worker verifies
signed rule bundles and nothing in the product signs one, so the feature is verify-only) and
**`LoadSignedFeed`** (no caller, no test, no reachable capability — delete).

| Symbol | Location | Note |
|---|---|---|
| `NewDecider` | `internal/agent/prefilter/decider.go:48` | **SUPERSEDED** — the prefilter is constructed by the agent through another path. The prefilter decider. |
| `NewDecompressGuard` | `internal/agent/sandbox/decompress.go:40` | **DELETED (D297)** as the weaker of two implementations. **DUPLICATE** — `internal/classify/documents.go` implements its OWN expansion and depth bounds. TWO implementations of one safety property is its own risk — worth collapsing, not wiring. Decompression-bomb guard (T-012). |
| `NewDepthTracker` | `internal/agent/sandbox/decompress.go:73` | **DELETED (D297)** as the weaker of two implementations. **DUPLICATE** — same. Archive nesting-depth tracker. |
| `EnterArchive` | `internal/agent/sandbox/decompress.go:77` | **DELETED (D297)** as the weaker of two implementations. **DUPLICATE** — same.  |
| `LeaveArchive` | `internal/agent/sandbox/decompress.go:86` | **DELETED (D297)** as the weaker of two implementations. **DUPLICATE** — same.  |
| `CreateEK` | `internal/attest/ek.go:22` | **WIRED (D314)** — created for the enrollment handshake by both the fleet agent (`OPENSHIELD_ATTEST_SELF_ENROLL`) and `attest-capture`. |
| `FlushEK` | `internal/attest/ek.go:38` | **WIRED (D314)** — released after self-enrollment. A TPM has few object slots; an EK left loaded consumes one for the process's life and the next key fails with an out-of-memory error naming nothing about this program. |
| `MarshalEnrollments` | `internal/attest/enrollment.go:52` | **WIRED (D314)** — `openshield-provision attest-capture` writes the gateway enrollments file. It had no caller, so the documented alternative to network enrollment had no tool that could produce one. |
| `ExtendPCR` | `internal/attest/pcr.go:44` | **PARTIAL** — same. PCR extension. |
| `DumpArgs` | `internal/backup/backup.go:34` | **NOT BUILT** — backup is designed, not driven by any command. Backup dump arguments (PLAT-9). |
| `Script` | `internal/backup/backup.go:81` | **NOT BUILT** — same. Backup script generation. |
| `NewWithEDM` | `internal/classify/classify.go:62` | **SUPERSEDED** — the worker layers indexes with `AddEDM`; the capability IS reachable. Exact-data matching classifier variant — DLP-4. |
| `BuildEDMIndex` | `internal/classify/edm.go:137` | **SUPERSEDED** — `openshield-dlp-index` builds indexes through its own path. Builds the EDM index the above consume. |
| `NewWithRecordEDM` | `internal/classify/edm_record.go:154` | **SUPERSEDED** — worker uses `AddRecordEDM`. Record-level EDM classifier variant. |
| `NewWithIDM` | `internal/classify/idm.go:158` | **SUPERSEDED** — worker uses `AddIDM`. Indexed-document matching classifier variant. |
| `SignRuleBundle` | `internal/classify/rules.go:79` | **BUILT (D297).** **TOOLING GAP** — the worker VERIFIES signed rule bundles; nothing in the product SIGNS one. An operator cannot produce the bundle the worker is built to load. Signs a classifier rule bundle. |
| `StopMediating` | `internal/clipboard/x11/x11.go:202` | **PARTIAL** — clipboard mediation has no teardown caller; a leak at shutdown, not a missing capability. X11 clipboard mediation teardown. |
| `NewProducer` | `internal/connectors/usb/usb.go:45` | **WIRED (D312/D313)** — `SysfsSource` reads `/sys/bus/usb/devices`, the engine polls it, the policy sees the device and the enforcer can act on it. |
| `Produce` | `internal/connectors/usb/usb.go:88` | **NOT BUILT** — same.  |
| `ExpirePendingApprovals` | `internal/controlplane/approvals.go:183` | **WIRED (D290).** Approvals never expire in a running deployment. 'A request left open for a week is not consent' — but nothing closes it. |
| `ReleaseLegalHold` | `internal/controlplane/cases.go:116` | **WIRED (D290).** Holds can be placed and never released. |
| `OpenCase` | `internal/controlplane/cases.go:132` | **WIRED (D290).** Operator case opening. Playbooks reach OpenCaseForIncident; a human cannot open a case. |
| `AssignCase` | `internal/controlplane/cases.go:160` | **WIRED (D290).** Case assignment. |
| `AddNote` | `internal/controlplane/cases.go:173` | **WIRED (D290).** Case notes. |
| `RequestClose` | `internal/controlplane/cases.go:189` | **WIRED (D290).** Case-close request — the first half of the four-eyes case closure. |
| `ApproveClose` | `internal/controlplane/cases.go:210` | **WIRED (D290).** Case-close approval — the second half. The whole four-eyes closure is unreachable. |
| `PublishFleetControl` | `internal/controlplane/fleetcontrol.go:75` | **SUPERSEDED** — by `PublishFleetControlSeq` (D287); the wrapper is now sugar. Superseded by PublishFleetControlSeq (D287); the wrapper is now unused. |
| `VerifySigned` | `internal/controlplane/identity.go:141` | **UNUSED SIBLING** — telemetry verification runs through a different entry point.  |
| `SetIntentBlastRadius` | `internal/controlplane/intent.go:64` | **WIRED (D291).** The blast-radius ceiling on intents. Never set, so never enforced. |
| `PublishIntents` | `internal/controlplane/intent.go:79` | **WIRED (D291).** SOAR-7's ENTIRE response-intent producer. The IdP responder IS wired and verifying — it listens for a message nothing in the product can send. |
| `RequestIntentApproval` | `internal/controlplane/intent.go:141` | **WIRED (D291).** The four-eyes request for an intent. Unreachable with its publisher. |
| `RollbackTo` | `internal/controlplane/settings.go:195` | **WIRED (D292).** Configuration rollback (D263). Revisions are recorded and cannot be rewound. |
| `CheckPurpose` | `internal/core/validate.go:117` | **UNUSED SIBLING** — same. Purpose validation (D20). |
| `ValidateDecision` | `internal/core/validate.go:148` | **UNUSED SIBLING** — `core.ValidateEvent` is called; this one is not. Decision validation. |
| `Decrypt` | `internal/enforcers/encryptlocal/encryptlocal.go:65` | **WIRED (D293).** encryptlocal can encrypt a file. Nothing can decrypt it. |
| `NewDenyEnforcer` | `internal/enforcers/process/process.go:136` | **SUPERSEDED** — DENY_EXEC is enforced by the privileged agent's exec gate (`execipc`/`execmon`), not by an engine enforcer. A second implementation for a path that moved. The process DENY enforcer (HIPS-3). |
| `SetIntentResolver` | `internal/engine/engine.go:205` | **WIRED (D294).** The endpoint's intent resolver seam (XDR-6). |
| `EnforceAuditDropped` | `internal/engine/engine.go:353` | **UNUSED SIBLING** — a counter accessor with no reader.  |
| `SignUpdate` | `internal/gateway/signedupdate.go:15` | **SUPERSEDED** — publishers sign inline.  |
| `LoadSignedFeed` | `internal/nips/signed.go:183` | **MISCLASSIFIED — was not dead; WIRED (D297).** **DEAD** — no caller AND NO TEST — the only symbol in the audit with neither. Signed NIPS feed loading. |
| `VerifySignature` | `internal/notify/sign.go:42` | **UNUSED SIBLING** — notify signing is verified by the receiver, not here.  |
| `NewPack` | `internal/policy/embed.go:45` | **SUPERSEDED** — policy packs load via `SelectFromEnv`.  |
| `BuildEnrollment` | `internal/posture/enroll.go:17` | **PARTIAL** — posture enrollment is designed; the roster path is what ships. Posture enrollment. |
| `IssueClientCert` | `internal/provision/provision.go:113` | **NOT BUILT** — `openshield-provision cert` issues leaf certs by a different path. Client-certificate issuance for the access proxy. |
| `InterceptionCA` | `internal/provision/provision.go:163` | **NOT BUILT** — TLS interception is not enabled by any command. The interception CA. |
| `Wrap` | `internal/transport/queue/transport.go:34` | **SUPERSEDED** — queue wrapping happens at construction.  |


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


## Round 3 (D313–D314): what running the product found that reading it did not

Two more capabilities that every unit test passed and no deployment could use, plus three defects that
only appeared once real processes were connected:

- **The USB subject never reached the policy input.** `GetUsb` had one non-generated caller in the tree:
  a log line. A policy could not tell a memory stick from a file write, so the rule the default policy
  told operators to write could not be written. Nothing failed; the capability simply had no effect.
- **`posture.Enroll` had no caller.** The gateway served the attestation enrollment protocol —
  challenge, credential activation, pre-auth tokens, EK anchoring — and no shipped binary spoke it. With
  `MarshalEnrollments` also uncalled, BOTH routes into the verifier were closed, and because the verifier
  fails closed, enabling attestation refused every device.
- **Nineteen TPM tests had never run.** They skip without `swtpm`, which was installed nowhere. A suite
  of skips reads exactly like a suite of passes in a green log, and the roadmap said the chain was
  "swtpm-proven end-to-end".

### The defects that needed real processes

- **The USB enforcer advertised ALLOW**, enacting it as "re-authorise the controller". Coherent for one
  decision, incoherent for a stream: the kernel switch is machine-wide and decisions are per-device, so a
  permitted keyboard released a banned stick's block. It was the only enforcer in the tree advertising
  ALLOW — the tell, since ALLOW is the absence of containment.
- **The agent never issued `TPM2_Startup`**, and the setup ran on its MAIN PATH. Invisible on hardware
  (firmware starts a physical TPM); against a software TPM the agent hung before its ticker loop — no
  heartbeat, no telemetry, no log line, because every message came after the call that blocked. Enabling
  attestation silently disabled everything else.
- **The integration harness leaked its own build directory and Postgres container on every run.** Its
  `TestMain` sat in `harness.go`, a non-`_test.go` file, where `go test` never calls it. 33 containers and
  25GB accumulated until the root filesystem filled and the gate failed to LINK. No test could have caught
  it: a cleanup path's absence produces no failing assertion by construction.

### What to hunt next

The pattern is now three for three: **a protocol with a server and no client**, **a file format with a
reader and no writer**, and **a gated test whose gate is never satisfied**. Each is greppable. The third
is the cheapest — `go test ./... -v | grep SKIP` — and was the most expensive to have missed.


## Round 4 (D315): the same shape, three more times

**A READER WITH NO WRITER.** A shipped binary reads a file at startup; no tool in the project can produce
one. From inside the code it looks finished — the format is defined, parsed, validated, unit-tested — and
from outside it is unusable.

| File | Read by | Written by (before D315) |
|---|---|---|
| posture roster (`OPENSHIELD_POSTURE_ROSTER`) | gateway, access mode | nothing — and `posture-keygen` confidently produced the SUPERSEDED single-key shape, telling operators to install it as a variable the gateway no longer reads |
| interception CA (`OPENSHIELD_INTERCEPT_CA_CERT/KEY`) | gateway | nothing — `provision.InterceptionCA` had a long comment on why it must be separate from the fleet CA, and no caller |
| enrollments (`OPENSHIELD_ATTEST_ENROLLMENTS`) | gateway | nothing (fixed D314) |

The posture roster is the worst of the three, because the tool did not merely fail to exist — it existed
and produced the wrong artefact. An operator following `posture-keygen`'s own instructions ended up with
an inert posture channel and a single startup warning.

`internal/backup` was a fourth variant: not a reader with no writer but a **procedure with no runner**.
`DumpArgs`, `Script` and `DrillSteps` had no caller, so the thing protecting the SYSTEM OF RECORD — the
ledger every tamper-evidence claim rests on — was a package nobody could execute.

### A vacuous test I wrote and the mutation caught

The first version of the interception-CA separation test compared the two CAs' private keys and required
them to differ. The mutation that minted the interception CA with `provision.InitCA` — literally the
fleet CA constructor, the exact fusion the test exists to forbid — **passed**. Comparing two fresh
keygen outputs asserts that the random number generator works. The test now asserts the SUBJECT differs,
that the interception CA says what it is, and that it is not signed by the fleet CA.

### The running score

Four rounds, four greppable shapes:

1. A protocol with a server and no client (`posture.Enroll`).
2. A file format with a reader and no writer (three instances).
3. A gated test whose gate is never satisfied (`swtpm`, `xvfb`, `pg_dump`).
4. A procedure with no runner (`internal/backup`).


## Round 5 (D316): what running the SKIPS found, and a coverage number

The previous rounds hunted unwired CODE. This one asked a different question — **which tests have never
actually executed** — and got two answers.

### The 19 root-gated tests, run on the VM against current code

18 passed. **`TestFanotifyPermissionAnsweredForReal` failed, and had never passed since it was written at
T-011.** It marked `t.TempDir()`, and a plain directory inode mark does not deliver permission events for
files opened INSIDE that directory — the same kernel fact D224 paid for in `execmon`, where a directory
mark silently let a denied binary run. The test could only ever have failed; it had simply never run,
because it skips without CAP_SYS_ADMIN and the build host deliberately has none.

It also failed BADLY: the triggering open blocks in the kernel on the main goroutine, so an unanswered
event hung the test until Go's timeout panicked, naming nothing. It now triggers off the main goroutine
and fails in five seconds saying the caller is still blocked.

### Integration coverage, measured rather than asserted

**57% of 168 declared settings** are exercised by the integration suite. The largest coherent hole was
OIDC — eleven settings, the whole ZT-2 identity path, which decides WHO rather than which device — and it
now has scenarios. The remaining gaps are listed below and are the next work.

### The vacuous-negative trap, in its purest form

The first version of the OIDC scenarios signed tokens with ES256, which the verifier refuses outright as
an unsupported algorithm. Every token was therefore rejected before any property under test was reached,
so all six NEGATIVE scenarios passed — "expired token refused", "wrong audience refused", "forged
signature refused", all green, all proving nothing. One positive case failed and exposed it.

A negative test suite is only as good as the positive that proves its cases are reachable. This is the
same shape as a gated test that never runs: green means nothing when the code path was never entered.

### Still not covered (the next work)

Beaconing (5 settings), break-glass, ENCRYPT_LOCAL keys, JetStream/queue durability, the exec-gate
settings at integration level, CASB catalog, the ITSM/IdP integration runners, EDM/IDM indexes, the
attestation hardening knobs (EK roots, pre-auth tokens, enrollments file), and the external witness key.


## Round 6 (D317): an UNSATISFIABLE guard, and two more vacuous tests of my own

### The new shape: a control that cannot be satisfied

R34-2's enrollment pre-authorization token was enforced server-side — request field, constant-time
comparison, single-use accounting, all built and unit-tested — and `EnrollToken` **had no producer
anywhere in the tree**. A deployment that turned the guard ON could not be enrolled by any shipped
client: every request arrived with an empty token and was correctly, permanently refused.

That is worse than an unenforced control. An inert feature does nothing; this one made the CAPABILITY
IMPOSSIBLE, so the only way to run the product was with its own security guard switched off — and an
operator doing that would reasonably conclude the guard was broken rather than unwired.

**Shape #5: a guard with an enforcer and no way to satisfy it.** Greppable the same way as the others —
a proto field read on one side and written nowhere.

### Break-glass announced the harmless case and hid the consequential one

The config scope split promises that an override "applies AND is reported". The process announced only
the case where a dynamic env value was IGNORED — which changes nothing — and was silent when an override
was actually IN FORCE. A host deliberately not running what the console shows was visible only to
somebody who thought to query `/config`. Backwards: during an incident, "why is this host different" is
asked of logs first.

### Two more of my own tests were vacuous

Following D316's OIDC lesson, and it recurred in a new form:

- **`TestAnUnnamedFieldIsNotOverridden` measured its own patience.** It waited two seconds and asserted
  orchestration had not started — but the playbook loader runs on a TICK, so the absence proved nothing,
  and the mutation making break-glass a general env escape walked straight through. **The timing form of
  the vacuous negative:** "X did not happen" is evidence only if X would have been observable in the
  window.
- **The fix's first attempt was worse:** a second server as a clock. The loop is LEADER-ONLY, so two
  servers contend for the lock and the control silently loses — flaky rather than wrong, which is the
  worse failure. Resolved by making the single subject its own witness: both sources name a valid but
  DIFFERENT file, so the process announces either way and the announcement names the path. Assert WHICH
  VALUE WON rather than waiting for silence.

### The running score

Six rounds, five greppable shapes:

1. A protocol with a server and no client.
2. A file format with a reader and no writer (×3).
3. A gated test whose gate is never satisfied (×3, one of which had never passed).
4. A procedure with no runner.
5. **A guard with an enforcer and no way to satisfy it.**

And three ways a green test can mean nothing: it never ran (skips), everything was refused for an
unrelated reason (vacuous negatives), or the window was too short for the thing to have happened
(timing).


## Round 7 (D318): three correct behaviours that combined into a fatal one

### The agent could not survive a reboot

Not an unwired feature — an EMERGENT defect, and the first of its kind found here. Three behaviours, each
right in isolation:

1. The fleet agent generated a fresh keypair on every start.
2. Enrollment tokens are single-use.
3. SEC-2 deliberately refuses to replace an enrolled agent's public key, so a fresh token cannot
   overwrite an agent's key or un-revoke a revoked one.

Together: a restarted agent got `enroll status 401` **and exited**. A reboot, an upgrade or a crash took
the endpoint out of the fleet permanently, until an operator revoked the identity and minted a new token
— and from the console it simply stopped reporting, which is indistinguishable from a quiet machine.

No package test could have found it: each component behaved exactly as specified. It took starting an
agent, stopping it, and starting it again — which nothing did until a test about the SEQUENCE store
happened to restart a process.

The fix is not to weaken SEC-2 but to persist the key, exactly as the telemetry sequence already is.

### The configuration layer refused what the code creates

`OPENSHIELD_QUEUE_DIR` was declared `KindPath`, which validates existence — while `queue.Open` does
`MkdirAll` on it. Every first boot with offline queueing enabled failed, and the message ("path is not
readable") pointed at the operator rather than at the mismatch. Every OTHER `KindPath` field is a key, a
policy or a baseline the operator PROVIDES, where requiring existence is exactly right, which is why the
wrong kind here went unnoticed. New `KindOutputPath` validates the PARENT.

### A wrong mental model in my own test

The spooling scenarios stopped the CONTROL PLANE to simulate an outage. The agent publishes to the
BROKER, so nothing it could observe changed, its spool stayed empty, and the test concluded that spooling
was broken. The harness now has `StopBroker`, and the distinction is written down where the next person
will look.

### The running score

Seven rounds. Five greppable shapes, plus one that is not greppable at all:

1. A protocol with a server and no client.
2. A file format with a reader and no writer (×3).
3. A gated test whose gate is never satisfied (×3).
4. A procedure with no runner.
5. A guard with an enforcer and no way to satisfy it.
6. **Correct components that combine into a broken behaviour** — findable only by running the thing.

And four ways a green test can mean nothing: it never ran; everything was refused for an unrelated
reason; the window was too short; or the fixture could not have exercised the guard (a corrupt blob
fails before the overwrite check it was meant to prove).


## Round 8 (D319): the loop got 150x faster, and a detector got a real negative

### The gate was being run when it did not need to be

Running `make all` (about ten minutes, mostly the integration suite) after every edit is how a gate stops
being run at all. Reviewing what the full gate ACTUALLY caught over this session that a targeted
`go test ./some/package/` would have missed, the answer was exactly two classes:

- **Cross-compilation.** A file behind a `linux` build tag with no portable stub breaks the Windows and
  macOS builds while every package test passes on the machine you are sitting at.
- **The static declaration and fitness guards.** A setting read by a command but never declared; a test
  entry point in a non-`_test.go` file. These scan the whole tree, so no targeted run reaches them.

Everything else it caught was infrastructure — a full disk, a suite outgrowing its timeout — which a
faster loop surfaces sooner anyway. `make quick` runs exactly those checks in **4 seconds**. `make all`
still runs before every push.

### Writing a negative case is harder than it looks

The beaconing detector needed a "this is NOT a beacon" case. The first attempt used a repeating
27s/27s/6s gap pattern as "bursty" traffic — and it was reported as a beacon, correctly. Regularity is
1 − MAD/median, and the MEDIAN absolute deviation of a set where two-thirds of the values are identical
is ZERO, giving a perfect score. That robustness is the right design: an implant that misses a check-in
is still an implant. But it means a negative case has to be irregular THROUGHOUT, not mostly-regular
with interruptions.

The lesson generalises: a negative fixture has to be built against the metric the detector actually uses,
not against an intuition about what "irregular" looks like.


## Round 9 (D320): a capability the specs had forgotten

### Three settings whose only test bypassed them

`OPENSHIELD_CASB_CATALOG`, `OPENSHIELD_EDM_RECORD_INDEX` and `OPENSHIELD_IDM_INDEX` each name a
capability with a thorough package test — and each of those tests reaches the capability by calling into
the library directly (`casb.SetCatalog`, `classify.AddRecordEDM`). Nothing exercised the env read, the
parse, the process-wide install, or the reload loop. Shape 5 again: a feature with a test and no proof
that the configured file reaches the running binary.

The mutation that makes the point: delete `casb.SetCatalog(cat)` from the gateway while KEEPING the
`content-aware CASB active` log line. Every package test stays green, the operator sees the capability
announce itself at startup, and every sensitive upload to an unsanctioned service is forwarded. Only an
assertion on what the destination RECEIVED catches it.

### The order of a three-step reload test is the test

The hot-reload contract is a conjunction: an edit must take effect, AND a malformed edit must not. The
obvious way to write it — start unsanctioned, confirm blocked, break the file, confirm still blocked —
is vacuous in its most important step, because a reload that emptied the catalog on a parse error ALSO
yields "not blocked". Starting from SANCTIONED and withdrawing sanction inverts every assertion into the
direction an empty catalog cannot satisfy. Same three steps, same runtime, and now the mutation fails.

That is a sixth way a green test can mean nothing, and it is the one hardest to see: the assertions are
individually correct, and the ORDER is what makes them vacuous.

### The specs had lost a shipped capability

Writing the spec delta surfaced something bigger. The CASB requirements — written, reviewed and archived
with the change that shipped them — are not in `openspec/specs/exfil-channel-awareness/spec.md`. A sweep
comparing every archived change's requirement headers against its merged capability file finds the same
across roughly thirty capabilities: `audit-ledger` keeps 5 of 24, and the ones it dropped include
"Every entry commits to its predecessor" — the ledger's central claim.

The specs are not wrong; they are INCOMPLETE, which is worse in one specific way. A missing requirement
reads exactly like a capability that was never asked for, so the next person to work on the ledger will
find a spec that does not mention hash chaining and conclude it is theirs to design. The cause is the
archive step's "archive without syncing" option, taken repeatedly. Recorded here rather than fixed in
passing: reconstructing thirty capability specs from their archived deltas is its own piece of work, and
doing it silently inside a test change would bury it.


## Round 10 (D321): a setting whose type made its feature unreachable

The exec-verdict socket had never been exercised through a binary. Writing the first scenario that
starts the real engine with `OPENSHIELD_EXEC_IPC_SOCKET` produced this, immediately:

```
openshield-engine: invalid configuration:
  OPENSHIELD_EXEC_IPC_SOCKET=".../v.sock": path is not readable (from env)
```

The setting was declared `KindPath`, which requires the path to exist and be readable at startup. The
engine CREATES that socket. So the engine could not start with the setting set, and HIPS-3's
policy-backed exec verdicts were unreachable through configuration — a shipped feature nobody could turn
on. This is D318's `OPENSHIELD_QUEUE_DIR` bug exactly: the configuration layer refusing to boot without
something the code creates two hundred lines later.

**The other end was worse.** The privileged gate declared the same socket the same way, so the gate
refused to start unless the engine was already up. The gate sits in the exec path of every process on
the host and is built to fail OPEN when the engine is unreachable — that is ADR-8, and it is the reason
the feature is deployable at all. Requiring the engine's socket at startup makes it fail CLOSED before it
has run a line: install the agent, start it before the engine, and nothing on the box execs.

Neither end was visible to any test, and the reason is worth stating because it generalises: the package
tests construct the gate and the verdict server DIRECTLY, so nothing ever went through a binary's
configuration validation. A kind is only wrong at `main()`.

Fixed by declaring all four socket fields `KindOutputPath` (parent must exist; the leaf need not), and
guarded statically — any declared setting whose key ends in `_SOCKET` must be `KindOutputPath`. A type
error that made a feature unreachable deserves a check that costs nothing to run.

### The running score

Ten rounds, and the ways a green test can mean nothing now number six:

1. it never ran (a skip nobody noticed);
2. everything was refused for an unrelated reason (vacuous negatives);
3. the window was too short (timing);
4. the fixture could not have exercised the guard;
5. the negative was built against an intuition rather than the detector's actual metric;
6. **the assertions are individually correct and their ORDER makes them vacuous** — the reload case,
   where "still blocked" after a bad edit is also satisfied by an emptied catalog.


## Round 11 (D322): the source of truth had lost most of itself

The spec store had lost **170 of the 526 requirements** this project wrote, reviewed and shipped.
`openspec/specs/control-plane/spec.md` was one requirement long — the body of a single delta — with
thirty-six other changes' work gone. `audit-ledger` kept 5 of 24, and the missing ones included *"Every
entry commits to its predecessor"*, which is the ledger's central claim.

**Two failures produced it, and both report success.** One is the archive step's "archive without
syncing", taken repeatedly. The other is worse: when sync DID run it REPLACED the capability file with
the delta being merged into it. The surviving requirement in `control-plane` is not even the last delta
chronologically — it is whichever one was synced last.

### Why nobody noticed: the alarm was broken by the same event

A delta file is a list of `## ADDED Requirements` sections; a capability file is `## Purpose` then
`## Requirements`. Overwriting the second with the first destroyed the document STRUCTURE too, and
`openspec validate` had been failing on **37 of 75 capabilities**. A validator that is already red
reports nothing when it goes redder. This is the general shape worth remembering: *a check that has been
failing for unrelated reasons is not a check.*

### The harm is not that the specs were wrong

They were INCOMPLETE, and that is worse in one specific way: **an absent requirement is indistinguishable
from a capability nobody ever asked for.** The next person to open the ledger's spec finds no mention of
hash chaining and reasonably concludes the design is theirs to make. It also compounds, because every new
delta is written and validated against whatever the file currently says.

### Restoring unreconciled, and what that surfaced

The replay is ADDITIVE — 28 requirements exist in capability files with no archived source, authored
directly, and regenerating from the archive would have deleted them. A repair that loses requirements
while fixing lost requirements is not a repair.

Restoring text without reconciling it to the code immediately surfaced two live contradictions:
`enforcement` still requires that *"inline blocking within the permission window is not provided"* (HIPS-3
and NIPS-1 both do it now), and `decision-contract` still requires that the pipeline *"SHALL NOT invoke
any enforcer"*. Both were invisible while they were missing. That is the argument for restoring them as
written: a contradiction you can see is a decision waiting to be made, and one you cannot see is a spec
that quietly means nothing.

### The seventh defect shape

1. A protocol with a server and no client.
2. A file format with a reader and no writer (×3).
3. A gated test whose gate is never satisfied (×3).
4. A procedure with no runner.
5. A guard with an enforcer and no way to satisfy it.
6. Correct components that combine into a broken behaviour.
7. **A source of truth that loses its history through the tool meant to maintain it** — and a validator
   already failing loudly enough that the loss made no sound.


## Round 12 (D323): settling two contradictions, and a third finding

D322 restored 170 requirements without reconciling them to the code, on the principle that a
contradiction you can see is a decision waiting to be made. Two were settled here, and settling them
required establishing what the product actually prevents — which turned out to be a per-domain answer,
not a yes or no.

| domain | inline prevention today | mechanism |
|---|---|---|
| execution | yes | `FAN_OPEN_EXEC_PERM` answered `FAN_DENY` |
| network flow | yes | TPROXY drop at L4; gateway refuses before forwarding |
| print job | yes | CUPS filter refuses before the printer |
| clipboard paste | yes, where the display server allows mediation | X11 selection ownership |
| USB device | yes | sysfs deauthorization |
| **file open** | **no** | nothing answers `FAN_OPEN_PERM` |

### The old requirement was right, and is still right about files

The temptation was to call it obsolete. It is not. Its reasoning — *"the file was already read, that is
how it was classified"* — is a statement about an unavoidable ORDERING, not about an unfinished feature.
You cannot block an open on a classification that requires the open.

What expired is the GENERALIZATION. It was written when file access was the only channel and it
generalized to all channels; the channels that arrived since decide on a path, a destination or a device
identity, none of which requires reading content. So the replacement is per-domain, and each claim must
name its mechanism — a stronger anti-overclaim rule than the original, because "we do not prevent" is
unfalsifiable and ages badly, while "an exec is prevented by answering the permission event with DENY"
can be checked and can be wrong.

### A spec that UNDERSTATES is as useless as one that overstates

These two requirements are where the project states its central honesty commitment, so a reader checking
for overclaim found a spec claiming LESS than the product does. The same understatement was on the
README — `openshield-agent` was still described as *"deferred… inline blocking, not yet wired"* long
after D244 proved it denying execs on a live kernel — and in the DPIA template's suggested wording. Both
corrected. `docs/decisions.md` was deliberately NOT touched: it is a dated register of what was decided
when, and D49 and D94 were true when written.

### The third finding: the file-open prefilter has no caller

`internal/agent/prefilter` implements the two-tier answer to the permission-window problem, and `grep`
finds no reference to it outside its own package. The `inline-prevention` capability already carries a
requirement for it. Shape 5 again — a design with tests and no runner — and it is precisely why the file
row above still says no. Recorded, not fixed: wiring it needs a privileged agent mode marking
`FAN_OPEN_PERM`, a partial-classification path through the sandboxed worker, and a root-gated kernel
test.

### A guard that blocks ordinary work gets switched off

D322's guard demanded that every archived requirement be present. This change is the first to RETIRE
one, and it hit the guard immediately — twice over. Removal had to become expressible, or the only way to
retire a requirement would be to disable the check. Two fixes, both about survivability rather than
correctness:

- the tools replay operations IN ORDER and honour the last one, so removed-then-re-added is required
  again (a set of removals would have been wrong the moment the project changed its mind);
- they read ACTIVE changes as well as archived ones, because a removal only reaches the archive at the
  change's last step, and a guard that is red for the whole life of the work it exists to permit is one
  somebody turns off.

The refusal behaviour is what made this happen at all: the tools were built to FAIL on an unrecognized
delta section rather than skip it, so `REMOVED` had to be implemented instead of silently dropped. That
is the same refusal the original clobbering sync lacked.


## Round 13 (D324): the gate was green because nobody looked at CI

CI had been failing for **over a day — every run since 2026-07-27T00:24, sixty consecutive runs** — while
`make all` was green locally after every commit. One job of nine: `build (macos-latest)`.

The cause is a platform constant. `sockaddr_un.sun_path` holds **104 bytes on macOS** and 108 on Linux,
and the kernel does not truncate an over-long address — it refuses the bind with EINVAL, surfaced as
`bind: invalid argument`, a message naming neither the length nor the cause. `t.TempDir()` builds its
path from the TEST'S NAME, and a macOS runner's temp prefix is already ~48 bytes, leaving about 31 for
the name.

So the rule has a genuinely perverse shape: **a descriptive test name breaks the test, and a terse one
hides the bug until someone renames it.** `TestMismatchedResponseIDIsRejected` is 33 characters.

### Verifying a macOS fix without a Mac

The constraint is reproducible anywhere, because it is arithmetic on a path. Setting `TMPDIR` to a
53-byte directory on Linux makes its 108-byte limit exactly as tight as macOS's 104 against a real 49-byte
prefix — so passing there implies passing on macOS. Before the fix: 5 bind failures. After: none. That is
a better check than "it looks right", and it took one line of shell.

The fix is a `socketPath` helper that allocates outside the test-named directory **and asserts the
length**, so the failure lands on the author's machine instead of on a runner nobody watches. A static
guard in `internal/fitness` now rejects any `t.TempDir()`-derived socket path — and caught two in the
integration suite that I had written myself, in a file whose comment described this very limit.

### A test that poisoned its own next run

Chasing the CI failure surfaced a second one locally. `TestRealX11ClipboardRoundTrip` starts an Xvfb on
`:97` and killed it with SIGKILL, so Xvfb never removed `/tmp/.X97-lock`. Every subsequent run found the
display locked, started a server that exited immediately, and failed several seconds later with *"the
first poll of a non-empty clipboard reported no change"* — a message about the clipboard, for a fault in
the display. Same shape as the leaked containers of D313: a test whose cleanup does not clean up, whose
next run pays, and whose error message points somewhere else.

It also stayed invisible because `make test` runs `go test -race ./...` **without `-count=1`**, so an
unchanged package keeps serving a cached PASS. The gate had genuinely not re-run that test since it last
succeeded. Worth stating plainly: a green gate means "nothing that changed is broken", not "nothing is
broken".

### Skip on a broken environment, fail on a broken product

The real cause of the clipboard failure turned out to be neither the lock nor the code: an `xclip`
unpacked from a `.deb` into a home directory starts, accepts the write, stays alive, and never serves the
selection. The test now probes the toolchain with xclip reading back its OWN selection, bounded by a
context because the failure mode is a HANG rather than an error, and SKIPS when that fails.

This cannot hide a regression, which is the only reason it is acceptable: it fires only when the
environment failed before our code was reached. If xclip can read its own selection and our reader
cannot, that still fails. A half-working toolchain is the same situation as an absent one — which this
test already skipped for.


## Round 14 (D325): the same limit, on the product side

D324 fixed the TEST suite's exposure to the unix address limit. The product had the same exposure and no
guard: every socket setting was `KindOutputPath`, which checks the parent directory and nothing about
length.

The failure it produces is quiet in a particular way worth naming. The engine validates its
configuration, starts the verdict server, logs `exec-verdict IPC ACTIVE`, and only then fails to listen —
so the operator has a process that SAID the feature was on. The privileged gate, unable to reach a socket
that was never bound, degrades to its static path and fails open with an audit per exec, exactly as
designed. **Every component behaves correctly, the deployment does not work, and nothing names the
cause.** That is the shape this audit keeps finding: not a broken part, but a correct one reporting
success for something that did not happen.

### Reversing a decision, on the record

D321 met this exact question — should a socket be its own configuration kind? — and answered no, because
a socket kind would then have behaved identically to `KindOutputPath`, and a kind distinguished from
another only by its name is noise in a schema that drives a UI.

That reasoning was right, and its premise has changed: the two kinds now differ in BEHAVIOUR, which is
precisely what earns a distinct kind. The alternative considered and rejected — a length check inside
`KindOutputPath` keyed on the field's NAME ending in `_SOCKET` — would put a behavioural rule in a string
comparison, where the next setting called something else silently gets no bound.

Recorded as a reversal rather than done quietly. A decision register that only ever accumulates is one
nobody trusts to describe the code.

### Refusing what works is worse than a message that varies

The tempting simplification is to validate against 104 everywhere: one number, one message, no build
tags. It is wrong. A 106-byte socket path binds correctly on Linux, and refusing it would be rejecting
VALID configuration — leaving an operator with a correct value the product will not take and no recourse.
So the constant is the running platform's: 108 on Linux, 104 elsewhere.

The general form: a check that rejects working configuration is a worse defect than the one it prevents,
because the operator cannot route around it.

### What the check deliberately does not do

It catches a path too long to bind, knowable from the VALUE ALONE before anything is created. It does not
attempt permissions, a full filesystem, or a stale socket held by another process. A configuration layer
that pretended to predict a syscall's outcome would be wrong the first time the two disagreed, and would
then be the thing standing between an operator and a working deployment.


## Round 15 (D327): a test that asserted the right outcome through the wrong path

The webhook signature (SIEM-8b) binds a timestamp INTO the MAC — `HMAC(secret, "<ts>." + body)` — so a
captured delivery expires. Without that binding a webhook URL is an endpoint anyone who saw one delivery
can page an on-call team through, indefinitely, with a message the receiver has cryptographic reason to
trust.

The first version of the test aged the VERIFIER'S CLOCK past the tolerance and asserted the capture no
longer verified. It passed. Then the mutation — sign the body ALONE, leaving the timestamp unbound —
**also passed**.

The reason is worth keeping. `VerifySignature` checks the timestamp's freshness window BEFORE it computes
the MAC, so an aged capture is rejected on the window check whether or not the signature covers the
timestamp. The test asserted the correct OUTCOME ("a replay is rejected") through a path that never
touched the mechanism it claimed to cover.

What fixes it is asking what the attacker would actually do: replay the captured body and signature with
a **refreshed timestamp header**. That forces the MAC to be consulted, and the mutation now fails.

### A seventh way a green test can mean nothing

The list so far was: it never ran; everything was refused for an unrelated reason; the window was too
short; the fixture could not exercise the guard; the negative was built against an intuition rather than
the detector's metric; the assertions were individually right and their ORDER made them vacuous. Add:

7. **The assertion is satisfied by a cheaper check that runs first.** A defence in depth means an earlier
   layer can answer for a later one, and a test written against the OUTCOME rather than the MECHANISM
   will happily measure the wrong layer.

It generalises past signatures: any time a verifier does a cheap rejection before an expensive one, a
test of the expensive one has to construct input the cheap one accepts.

### And the fix was wrong once too, in a way that only showed on the clock

The corrected assertion forged the timestamp as `time.Now().Unix()` — which, when the delivery and the
assertion land in the SAME SECOND, is byte-identical to the captured one. The forgery is then a no-op,
verification correctly succeeds, and the test fails on correct code. It passed on one run and failed on
the next, three seconds apart, with nothing changed but a second boundary.

Deriving the forged value from the CAPTURED timestamp (`captured + 1`) makes it deterministic, and the
test now refuses to run at all if the two ever coincide — because a scenario that cannot tell its own
input apart is asserting nothing. Green three times running, and still killed by the mutation.


## Round 16 (D328): three scenarios, three assertions delivered by the wrong layer

The overdue/heartbeat batch produced the same failure three times in a row, in three different ways. It
is the sharpest pattern this audit has found, and it is not about any of the features involved.

**1. The assertion measured a different quantity than the mechanism.** The recovery step waited for the
agent's TOTAL telemetry rows to grow, while liveness is computed from `max(received_at) WHERE verified`
off the enrolled roster (SEC-3). The test would have called an agent recovered while the control plane
still, correctly, considered it silent.

**2. The premise was wrong, and the product was right.** The scenario asserted that an agent which
recovers and fails again is reported AGAIN. It failed — because delivery buckets a notification's
idempotency id into a 10-minute window, so a second page for the same agent inside one bucket is
deliberately suppressed. The end-to-end contract is ONCE PER AGENT PER WINDOW. The stronger claim is real
but needs a ten-minute wait to observe, so it is tested at the unit layer where the bucket is an argument
rather than a clock. **The test was rewritten to assert what the system actually guarantees, rather than
adjusted until it passed.**

**3. A property defended three deep looks vacuous under a single mutation.** "Reported exactly once"
survived mutating the rising edge, and survived disabling the in-memory dedupe, and survived both — which
read exactly like a test that proves nothing. It is not: there is a THIRD layer, a durable Postgres
dedupe (R34-13), and breaking all three makes the scenario see six pages instead of one.

That last one refines the seventh shape rather than repeating it:

> With defence in depth, a single mutation cannot falsify an assertion, and the test looks vacuous when it
> is merely well-defended. The way to tell the difference is to break EVERY redundant path — if the
> assertion still holds, it is vacuous; if it finally fails, it was load-bearing all along.

The comment in the test now names all three layers and says plainly that the scenario does not pin down
any one of them. A comment claiming it proved the rising edge would have been false, and would have been
believed.

### The estimate that was wrong by 4x

Asked whether a targeted run was really 30 seconds, the honest answer was no — it is 1m49s. The first
integration invocation builds the test binary AND the twelve product binaries into a temp dir, then each
scenario starts its own NATS container and database. Guessing at it twice was worse than measuring it
once.


## Round 17 (D330): a setting that bricks the host, found by testing it once

`OPENSHIELD_EXEC_ALLOW` — application whitelisting, default-deny — had never been exercised anywhere.
The first integration test for it asserted the obvious pair (an allowlisted binary runs, an unlisted one
does not) and failed. Investigating took the rooted VM down twice and needed an out-of-band reboot, which
is the clearest possible statement of the defect.

**Measured on a live kernel**, with an allowlist naming one binary in one monitored directory:

```
/home/coder/probe/bin/permitted-tool: Operation not permitted
/usr/bin/sudo:                        Operation not permitted
/usr/bin/cat:                         Operation not permitted
/bin/bash:                            Operation not permitted   ← sshd could not start a login shell
```

**The failure is unrecoverable in the way that matters.** Stopping the agent needs `sudo`; `sudo` needs
`exec`; `exec` is denied. Logging in needs a shell, also denied. The only exit is a power cycle.

### The cause was written down in the code, three years of good intentions ago

Exec-permission events are delivered only for a MOUNT mark — a directory inode mark does not deliver
`FAN_OPEN_EXEC_PERM` for files executed inside it (the D224 lesson). So `execmon.Open` marks the mount,
with a comment saying exactly that:

> This is broader than the named path (the whole mount); a later increment can narrow with per-file
> marks or path filtering.

For a **deny-list** the breadth is harmless: it refuses exactly what it names. For an **allow-list** it
is catastrophic, because the rule is *everything not named*, and "everything" turned out to be the
filesystem rather than the configured directories. Nothing carried the narrowing forward to the decision.

### The shape worth remembering

A known, documented over-approximation was safe for every consumer that existed — and then a consumer
arrived for which it was fatal. The comment was accurate, the code was as designed, and no test failed,
because the only test of the allowlist called the evaluator directly with paths of its own choosing. The
matcher was CORRECT in isolation; it was the scope it ran in that was wrong.

That is the sixth defect shape (correct components combining into a broken behaviour) at its sharpest,
and it argues for something specific: **when a control changes from enumerate-what-to-block to
enumerate-what-to-allow, its blast radius inverts, and every over-approximation upstream of it has to be
re-examined.** Default-deny is not "the deny-list with a different list".

### The fix, and what it deliberately does not do

The default-deny is now bounded by `OPENSHIELD_EXEC_MONITOR_DIRS`: an exec outside every monitored
directory is out of scope and permitted. The deny-list is deliberately left unscoped — an enumerated
refusal has a blast radius equal to what it names, so breadth costs nothing there, and narrowing it would
silently weaken existing deployments. An allowlist with no directory to bound it is now REFUSED at
startup rather than armed.

The mark itself is still broad, so the agent still answers a permission event for every exec on the
mount. That waste is real and is not fixed here; what is fixed is that the answer is now correct.
Narrowing the mark is separate work with its own kernel-level risks, and pretending otherwise is how a
scope fix becomes a rewrite.

### The guard learned the other half of its own lesson

Landing this tripped the spec-store check: an ACTIVE change's newly-ADDED requirement was demanded in the
capability file, which the sync only writes at archive — so the gate would be red from the moment a
change is proposed until the moment it lands. Active deltas are now honoured only where they RELAX
(REMOVED counts, ADDED does not), which is the mirror of the removal fix in D323. Both come from the same
rule: a guard that blocks ordinary work is a guard someone switches off.


## Round 18 (D331): fixing the waste, without turning it into a bypass

D330 fixed the exec allowlist's DECISION and left its COST: the agent answered a permission event for
every execution on the marked mount, each one blocking the executing process for a readlink and a kernel
round-trip. That is a tax on every process launch, paid for executions the gate had already decided it
does not police.

### Measure first, because this is exactly where the wrong answer was learned before

The mount mark exists because a narrower one was tried and did not deliver (D224). So all three shapes
were measured on kernel 6.8 rather than read from a man page:

| mark | direct child | nested | outside |
|---|---|---|---|
| mount | delivered | delivered | not delivered |
| directory + `FAN_EVENT_ON_CHILD` | **EINVAL — refused outright** | — | — |
| per-file | delivered | not delivered | not delivered |

`FAN_EVENT_ON_CHILD` would have been the best answer — one mark per directory, new files covered by the
kernel — and it is simply not available for exec-permission events. That has now been rediscovered twice,
so it is a test that prints its result rather than a comment that can be doubted.

**The `outside` column also reframes D330.** It reads "not delivered" for the mount mark because the
probe ran under `/tmp`, which is **tmpfs — a different mount from `/`**. That is why the damage varied by
location: a monitored directory under `/opt` marks `/` and takes `sudo` and `bash` with it, while one
under `/tmp` marks only tmpfs. A blast radius that depends on where the operator points it is worse than
a constant one, because nothing about testing it in one place predicts the other.

### The asymmetry that decides the design

Per-file marking can only MISS. The mount mark can only WASTE. In a security control those are not
symmetric, so narrowness is applied only where the scope is already defined and defended:

- **allowlist → per-file.** D330 bounded its reach to the monitored directories, so an execution outside
  them is out of scope by definition and an event for it is pure cost.
- **deny-list, behavioural floor, pipeline verdict → mount.** Each names or decides on binaries wherever
  they run from. A deployment combining them with an allowlist gets the union, which is global.

### The hole that would have made this a bypass

A per-file mark covers what existed when it was applied. Under default-deny an unmarked binary produces
NO event and therefore RUNS — so a naive narrowing hands an attacker something better than being
allowed: an execution that is also invisible. Closed with an inotify watch marking on create, move-in and
close-after-write (close-after-write matters because a file is typically created empty and made
executable later).

Proven on the real kernel, and the mutation is the point: with the watcher removed, a binary DROPPED into
a watched directory runs, and so does one MOVED in. Both scenarios fail. That is the assertion that
separates an optimisation from a bypass.

**The residual race is stated, not hidden:** a binary created and executed before the watcher's mark
lands escapes. The window is bounded by scheduler latency rather than by an operator noticing, which is
the improvement — but it is not zero.
