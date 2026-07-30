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


## Round 19 (D333): two settings nothing read, and a correction

The `config` package's doc says a DERIVED schema makes it "structurally impossible" for a surface to
offer a field the binary never reads. Derivation delivers that for a field the code never had. It does
not cover **a field whose reader was later deleted** — and that had happened twice, undetected, in 170
declarations.

### The existing guard declines this question, for a good reason

`TestEveryEnvReadIsDeclared` checks that a read in a command's own code is declared, and says explicitly
why it does not check the reverse: a binary's configuration surface includes what its LIBRARIES read
(`OPENSHIELD_POLICY_PACK` in `internal/policy`, `OPENSHIELD_JETSTREAM` in `internal/transport/nats`), so
a command-scoped reverse check would flag both as dead, and a module-scoped one "would mark every
variable as read by every binary, which proves nothing".

Right about the per-binary question, and it leaves a different one open: **is this key read AT ALL,
anywhere?** Module-scoped, that has a definite answer, and it is exactly the dead-setting question.

### The comment is the symptom, not an excuse

`OPENSHIELD_POSTURE_PUBKEY` appears in the gateway's source — inside a comment explaining that the
gateway no longer reads it. A naive text search therefore finds it and concludes it is alive. Prose
documenting a retirement is the strongest available evidence a setting is dead, so the check strips
comments; without that it passes on precisely the shape both findings had.

### Two dead settings, two opposite fixes

`OPENSHIELD_POSTURE_PUBKEY` names a mechanism SEC-12 deliberately replaced — one fleet-wide key any agent
could use to forge another's posture — so the setting is wrong and removal is the fix. Wiring it would
resurrect the vulnerability that motivated the replacement.

`OPENSHIELD_NOTIFY_DEDUPE_RETENTION` names behaviour that is wanted and already implemented, so the
setting is right and the READ was missing. **A correction belongs here: my first reading of this said the
prune had no caller at all and the table grew forever. It does have a caller — a broken shell
substitution found nothing and I believed it.** What is actually wrong is narrower and nastier: the loop
pruned on a cutoff hardcoded to 24 hours, and then recorded a compliance event whose policy string was
the literal `OPENSHIELD_NOTIFY_DEDUPE_RETENTION=24h`. An operator who set 7d had their value ignored AND
got a retention record naming their knob while asserting a value they never chose.

**A compliance record that cites a setting nobody read is worse than one that omits it — it is evidence
of a policy that was never applied.**

The check reports that a setting has no reader. It cannot tell you whether to add one or remove the
setting; treating it as if it could would have produced exactly the wrong change in one of these two.


## Round 20 (D335): a setting that cannot do what its description promises

`OPENSHIELD_CLIPBOARD_EXCLUDE` said: *"Applications whose copies are never read — password managers and
the like. Exclusions are applied BEFORE the read."* The claim is a privacy one and stronger than "we do
not alert on it": a DLP agent that reads a credential and then decides not to report it has still
ingested it, into a security product's memory.

Testing it needed a real X server — the source is identified from the SELECTION OWNER, window to pid to
executable, and there is no way to fake that. The build host's hand-unpacked xclip cannot round-trip a
selection and CI has no X at all, so it had never run. The VM has both.

**It does not work in the default mode, and did not say so.** In polled-helper mode the engine reports
`source-attribution=false` — the owner is not knowable, every copy is unattributable, and an
unattributable source is deliberately NOT excluded (excluding them all would silently disable monitoring).
So the exclusion has no effect, and the setting's description promised the opposite.

**Under mediation it is better and still conditional.** The capability report says
`source-attribution=true`, which is true of the MECHANISM rather than of every copy. Measured: a copier
that forks and exits — which is what `xclip` does, and hardly exotic — is unnamed by the time `/proc` is
read, so the copy has no attributable source and the exclusion does not fire.

### What was actually wrong was the silence

The code already logged that case, framed as *"the shape a deliberate evasion takes"* — accurate, and not
what an operator needs first. It did not say the CONSEQUENCE: that a configured exclusion did not fire and
the content was read. Nothing anywhere connected "attribution failed for this copy" to "your exclusion
did not apply".

Both messages now state it, and the setting's description states the dependency: exclusions need
mediation AND an owner that can be named, and in polled mode, on Wayland, or for an unnameable copier the
content IS read.

### The shape

This is not an unwired feature — every piece works as designed and the design is defensible. It is a
CLAIM SURFACE that outran the mechanism: a description written for the capability's best case, in a
product whose default is the worst one. The test that found it is the first that ever ran the feature.


## Round 21 (D336): measuring coverage by what runs, not by what is configured

Settings coverage was a PROXY, and proxies drift from the thing they stand for. Two better measurements
replaced it, and both immediately found what the proxy could not.

### Every test in the suite now provably executes

The full suite, run as root on the VM (which has podman, a real X toolchain and a permission-capable
kernel): **136 pass, 0 fail, 0 never-run.** The last holdout was the backup/restore drill, skipping
everywhere for want of `pg_dump`; installing the postgres client on the VM ran it for the first time.
`TestRealX11ClipboardRoundTrip` likewise ran for the first time since it was written.

That closes the "run the skips" hunt (D316): a test that skips on every machine it can reach is not a
test, and this suite no longer has one.

### Real coverage of the product, measured

Binaries built with `-cover -coverpkg=./...`, the suite run against them with `GOCOVERDIR` set:
**77 packages, mean 51.2% of statements**, with **13 packages the suite never reached at all**.

Four of the thirteen are covered only when the suite runs on the VM (`agent/watchdog`, `clipboard/x11`,
`dnsredirect`, `dnssink`) — which is an argument for running it there routinely, not a gap. The rest were
genuinely untouched everywhere, and they cluster:

    connectors/syslog, connectors/rfc5424, connectors/cef   the SIEM-4 log-ingest family
    connectors/dns, connectors/execaudit, connectors/limiter  producers and the rate limiter
    internal/signature                                       NIPS content signatures
    internal/release                                         release manifest + verification

### What the proxy could not see

Nine subcommands are never invoked by the suite, including `openshieldctl timeline` — which is T-010's
entire deliverable. Phase 1 CUT the React investigation UI and put the timeline in its place, making it
the only way an operator reconstructs an incident. A settings audit cannot see it, because subcommands
take FLAGS: a binary's executable paths are not enumerable from its configuration.

Also invisible: `openshield-server restore`, `openshieldctl verify-release`/`release-manifest`/`anchor`,
`openshield-provision attest-capture`/`risk-keygen`.

### And the first test of a listener found its protocol

The CEF-over-syslog listener binds **UDP**, not TCP — the first scenario dialled TCP and waited a minute
for a port that was never going to open. Worth recording beyond the fix: syslog over UDP has no delivery
guarantee and no backpressure, so a burst that outpaces the reader is dropped by the kernel with no error
at either end. The tests resend while waiting and assert on the STORE rather than the send, for the same
reason a real estate loses events.


## Round 22 (D337): the one ingest path with no reliable option

Asked whether UDP was adequate for an audit path, the answer was no, and the reasons were verifiable
rather than a matter of taste:

- **The loss is structurally invisible.** `Listener.Dropped()` counts messages that FAILED TO PARSE — ones
  the application received. A datagram the kernel discards for want of buffer never reaches the
  application, so no counter it keeps can observe it. That is the silent gap D31 forbids, on the one
  ingest path carrying somebody else's evidence.
- **The RICH event is the one most likely to vanish.** The buffer is sized to the line bound and a larger
  datagram is truncated by the kernel, after which the parser rejects it — so a CEF event with a realistic
  extension set fails as "malformed device" rather than "MTU".
- **The sender is anonymous.** Anything that can reach the port can inject events into a store operators
  are invited to treat as evidence, and fabricated evidence is worse than lost evidence.

Meanwhile the product asserts the opposite discipline everywhere else: the endpoint spool makes an outage
a GAP THAT FILLS IN, and durable telemetry ingest acknowledges only after persistence with at-most-once
as an explicit opt-out. External logs had at-most-once with no opt-in to anything better.

### The honest claim is narrower than "no loss"

A stream removes kernel-level silent drop and adds backpressure. It does NOT acknowledge PERSISTENCE — a
process killed with buffered data still loses it, and no syslog device implements an application-level
ack. So the claim stated in the spec is: **loss now requires a crash or an explicit refusal, both
observable, rather than a buffer quietly filling.** Anything stronger would be the overclaim this project
exists to avoid.

### Two things the tests taught

**A TLS 1.3 refusal does not appear at the handshake.** The client sends its certificate in its last
flight and proceeds; the server verifies afterwards and sends an alert. So `Dial` and `Handshake` both
SUCCEED against a server about to refuse you, and the refusal surfaces on the first READ. The first
version of the scenario checked only the handshake and concluded the listener accepted anonymous senders —
about correct code. A read timeout means accepted; an alert or EOF means refused.

**Framing auto-detection is ambiguous, and the ambiguity must not be fatal.** RFC 6587 allows
octet-counted and newline-terminated framing, and real senders use both. A newline-framed message that
merely BEGINS with a digit looks like an octet count until the number fails to parse — so that case is
counted and skipped rather than closing the connection, because one such message would otherwise stop a
device's whole feed.


## Round 23 (D338): the privacy assertion that could not run

`internal/signature` measured at zero integration coverage, so NIPS content signatures got scenarios —
a marked body blocked before it leaves, a `nocase` rule matching a differently-cased marker, a malformed
ruleset stopping the worker, hot reload served-stale. Writing the content-free half found something worse
than an uncovered package.

**The ledger has no `payload` column, and never has.** The existing assertion in `gateway_test.go` read:

```go
if err := pool.QueryRow(ctx, `SELECT coalesce(payload::text,'') FROM audit_entries LIMIT 1`).
    Scan(&payload); err == nil {
    if contains(payload, "111.444.777-35") { t.Errorf("the proxied BODY reached the ledger") }
}
```

The query errored on every run, `err == nil` was never true, and the body of the check never executed. So
the project's **most important privacy claim** — no content reaches the audit trail (D10/D29) — was
guarded by code that could not run, in the one place the claim is most load-bearing: a DLP product whose
evidence store contains the evidence.

This is the fourth way a green test means nothing, met again and at its sharpest: **the fixture could not
have exercised the guard.** Here the guard was not merely weak, it was unreachable, and the `err == nil`
made unreachability look like success.

### The fix has to be un-missable, not merely correct

Naming the right column would work until someone adds another. `assertLedgerCarriesNone` casts the WHOLE
ROW (`audit_entries::text`), so it cannot name a wrong column, it covers columns added later, and a query
error is a FAILURE rather than a skip — because an assertion that cannot run must never look like one
that passed. It also fails when zero rows were checked, since passing over an empty ledger proves nothing
about a pipeline that was supposed to write to it.

### And the mutation nearly lied too

The first mutant leaked content by concatenating a string to `reason` — which is a `*string`, so it did
not compile, and both tests "failed" on a broken build. That would have been recorded as a successful
verification. Only re-checking `go build` before believing the result caught it. A mutant that does not
compile proves nothing, and it fails in exactly the way a successful mutation looks.


## Round 24 (D339): the verification that could not tell who signed

`internal/release` measured at zero integration coverage and both of its subcommands —
`openshieldctl release-manifest` and `verify-release` — had never been invoked by the suite. A poor
place for a gap: this is the code that decides whether the thing running as root on every endpoint is
the thing the project built, and a supply-chain control nobody has executed end to end is a README.

The scenarios exercise the operator path — sign a directory with one command, check it with another —
and every refusal holds: a byte changed at the same length, an artifact added after signing, an
artifact removed, and a manifest rewritten to match a swapped binary (rejected on the signature, not
the digests, because a coherent forgery has correct digests). The SBOM is real too — built from the
binary's recorded module graph, so the staged release includes an actual Go binary; over non-binaries
the SBOM generates successfully and says nothing, and the assertion would have passed against it.

### What the coverage exercise actually found

`verify-release` reads its public key from the **same directory it is verifying**. So an attacker who
can modify a download can swap a binary, re-sign the entire set with a key of their own, replace
`release-key.pub`, and pass verification — every digest matches a manifest signed by a key that is
present. The command answers *is this set internally consistent*, and an operator who runs it and sees
`verified 4 artifacts` reasonably believes it answered *did the project sign this*.

No amount of care inside the verifier closes that, because the entire input is the attacker's. The
fix is not a better check but a second input: `--key`, a public key obtained out of band.

### The fallback is the bypass

When `--key` is supplied the shipped key is **not read at all** — not on an unreadable pin, not on a
malformed one, not on a mismatch. A fallback would reintroduce the whole gap through the error path,
and an attacker who can modify the download can usually arrange the condition that triggers it. Both
mutations confirm this is load-bearing rather than decorative: falling back when the pinned key fails
to verify makes the re-signed release pass, and treating an unusable pin as absent makes all three
unusable-pin cases pass.

The unpinned path stays, because checking that a download was not corrupted is worth doing before an
operator has any key. What does not stay is the silence: it now prints what it did and did not
establish, and how to establish the rest. D31 applied to the supply chain — the limit that is not
stated becomes a false belief, and here the belief is about the binary running as root.

### Testing a limit you intend to remove

The first version of this asserted the gap: it re-signed a release with an attacker key, confirmed
`verify-release` accepted it, and logged the reason. That test is worth writing — a demonstrated
limitation is much harder to forget than an assumed one — but it is worth keeping only until the
limit is closed. It is now the *unpinned half* of the pinning test, where it still asserts something
true and sits next to the pinned half that refuses the same directory. The difference between the two
runs is one flag and nothing else, which is what makes it about the key rather than about the release.


## Round 25 (D340): the backup nobody had restored

`openshieldctl backup dump`, `backup drill` and `restore-verify` had never been invoked by the suite.
`internal/backup` was written with care — it owns the pg_dump arguments so they are not retyped from a
wiki, and it owns the ORDER so a restore is not called finished until the ledger re-verifies — and
until D315 it had no caller at all. Even after it got one, no scenario had ever taken a dump and
restored it. The ledger is tamper-evident, forward-secure and anchored, and all of that is worth
nothing against a disk failure if the recovery procedure is a package in a repository.

The drill now runs for real: engine writes entries, the anchor witnesses the head, `backup dump`
produces a file, `backup drill` restores it into a **separate database** on the same server and runs
the verification step, which reports the restore confirmed. The separate database matters — a drill
that restored over its source would destroy the thing it is proving recoverable, and would let a
restore that did nothing at all pass, because the data was already there.

### Three ways this test tried to lie

**The append-only guard refused the truncation.** Constructing a truncated ledger by `DELETE` fails:
migration 010's trigger forbids it. That is the product working, so it is now asserted on the way past
rather than worked around silently — a restore that quietly dropped the guard would be a real defect.
The truncation is then constructed the way real loss produces it, by disabling the trigger as the
table owner, which is the credential a recovery operator actually holds and stands in for rows that
never arrived.

**`contains(out, "consistent")` also matches `consistent=false`.** The premise assertion — that a
truncated chain still hashes perfectly — passed against a ledger reported as INCONSISTENT. It now
requires `consistent=true` in full. This is the sixth failure mode with a new face: an assertion that
is individually reasonable and matches its own negation.

**A surviving mutation was the honest signal.** Removing the completeness requirement from
`restore-verify` did not fail anything, which read as vacuity. It was not: truncation past an anchor
is caught TWICE, once by `checkAnchors` setting `Consistent=false` and once by the completeness
branch. Breaking either leaves the other. Only breaking BOTH makes the DAMAGED assertion fail — which
is the corollary this audit already knew and had to apply again: with defence in depth, a surviving
mutation means "try harder", not "the test is fake".

### And the mechanism was described wrongly

The first version claimed only completeness could catch truncation. What actually holds is sharper:
verification WITHOUT the witness key reports a perfectly consistent chain and `completeness=unverified`;
the same command WITH the witness key refuses. One extra input inverts the verdict, because the anchor
was written when the head was further along. The test now asserts both halves, so it is about the
anchor rather than about `restore-verify` in particular.

### One more instance of D338's dead assertion

`observe_test.go` carried the same `SELECT ... payload::text` query against a column that does not
exist, wrapped in the same `if err == nil`. It had never executed either. Both are now
`assertLedgerCarriesNone`. Worth recording that the pattern appeared twice: a query guarded by
`err == nil` is not a check, and grepping for that shape is cheaper than finding them one at a time.


## Round 26 (D341): the third detector that never became a decision

`internal/connectors/dns` measured at zero integration coverage. Driving it found that
`dns.TunnelScore` — the covert-channel heuristic, written, documented and unit-tested — had **no
caller outside its own package**. `ToEvent` never computed it, no policy read it, nothing downstream
saw it. Meanwhile `cmd/openshield-engine/dnssource.go` stated in its own doc comment that
"DNS-tunnelling detection (dns.TunnelScore) become live rather than parser-only".

That is the third instance of one shape:

- **D300** — no shipped policy read `input.threat`. NIPS-2 matched operator indicators, logged that
  it was active, and handed the match to a decision layer that ignored it.
- **D301** — the exec producer omitted a provenance field, so every engine-backed exec decision
  errored and the watchdog fail-opened, while every log line said inline prevention was active.
- **This** — the signal was computed nowhere, and the comment said it was live.

Three is enough to name it: **the feature exists everywhere except at the point where a signal
becomes a decision, and the logs report it working.** Detector, wiring, config and docs can all be
present and correct, and the one missing line is the comparison that turns a number into an action.
It survives review because every individual piece is right, and it survives testing because unit
tests cover the detector and integration tests cover the connector, and neither covers the seam.

The cheap check is a grep: an exported detector function with no non-test caller.

### The design call worth recording

The obvious wiring was to reuse `input.event.behavioral.score`, which the default policy already
alerts on at 0.5. That was rejected for two reasons about meaning.

`behavioral` is `{score, lolbin, suspicious_lineage, encoded_command}` — a PROCESS verdict. A DNS
query has no LOLBin, so reusing the key emits `lolbin: false`: false rather than absent, which a
policy author reads as "checked and clean". **Absence is information; a fabricated `false` destroys
it.** And `default.rego` documents that network events have no `behavioral`, so populating it would
start firing every existing operator policy on DNS traffic without anyone editing a policy — a
behaviour change delivered through a vocabulary change, which is the hardest kind to notice.

So DNS got its own key, following the CASB `cloud` precedent already in the mapping layer. The
threshold travels in the input beside the score, so the comparison is visible in `default.rego`
rather than buried in Go where no operator reading the policy could see it.

### Alert, never block — sharper here than elsewhere

A rule that blocked would deny NAME RESOLUTION on a heuristic over a single query with no session
context. That presents to a user as "the internet is down" and to an operator as nothing in
particular.

### And the ledger assertion matters more here than anywhere

In a DNS tunnel the exfiltrated data IS the query name. An audit trail that recorded it would
republish the exfiltration it exists to detect, into the most copied and longest-retained store in
the system. A detector whose evidence is the disclosure is worse than no detector, because it also
creates the record. The decision reason names the signal and never the name.


## Round 27 (D342): an entire connector that no binary could start

D341 ended by naming the cheap check for the shape it had just found for the third time: an exported
detector with no non-test caller. This is that check's first run, against the code graph rather than
grep, and it found something larger than a missing comparison.

**`internal/connectors/smtp` was imported by nothing.** A session parser, a capture listener with
per-session size ceilings, idle timeouts and a concurrency cap, an event producer, and unit tests
covering all of it — and no binary imported the package, with **no configuration setting that could
have turned it on**. It could not run in any deployment, however configured. Meanwhile the README
described the product as performing live SMTP inspection, listed it as a gateway capability, and drew
it as a pipeline source.

Two other whole packages came back from the same query — `internal/ztna` and
`internal/agent/prefilter` — and are recorded here rather than fixed, because each needs its own
judgement about whether the right answer is to wire it or to stop claiming it.

### The graph found what grep could not

The check needs "exported symbol with no NON-TEST caller", which is a join across the call graph, not
a text pattern. It also found the piece that made the fix correct: `engine.SetContentResolver`, and an
existing `internal/engine/content_test.go` whose fixture is *already an SMTP event*. The mechanism for
getting an email body to the sandboxed worker had been built and tested too — for the connector that
was never started.

The query has false negatives (it flagged `exfil.Classify`, which is called), so every hit was
confirmed with grep before being believed. A graph that is wrong in the safe direction is still worth
running; one whose output is taken on trust is not.

### The body travels out of band, and the store must precede the send

`smtp.ToEvent` carries the envelope only. The body goes into a content store the engine's resolver
consults, so it reaches the worker and nothing else (D72) and never touches the Event or the bus
(D10/D29).

Two details that would each have been a silent defect:

- **`store.Put` before the channel send.** The pipeline can begin classifying the instant the event is
  received, so storing afterwards races the resolver — and a resolver that returns nothing yields an
  empty classification, which downstream is indistinguishable from clean content. A scan that did not
  happen would have looked exactly like a scan that found nothing.
- **The resolver is CHAINED, not assigned.** It holds exactly one function, so an assignment would
  silently disable clipboard or print classification for anyone who enabled both. The print socket
  already chains over the clipboard store; this follows it.

### The test proves classification, not parsing

The alert requires a CHECKSUM-VALID CPF. Delivering a CPF-SHAPED value with wrong check digits raises
no alert — so the passing case is a real detection and not a shape match, and the body demonstrably
reached the worker. Withholding the body from the store fails the scenario the same way.

### The README now says what runs where

"DNS/SMTP inspection" was attributed to the gateway. DNS *sinkholing* is the gateway; DNS query and
SMTP message inspection are the engine. The claim is now true and it names the right binary — which
matters more than it looks, because an operator reading it configures the wrong process otherwise.


## Round 28 (D344): the reproducible half of the thesis had never been run

The roadmap states the project's thesis in one sentence: *every security decision is explainable,
**reproducible**, and cryptographically auditable*. `openshieldctl verify` has always covered the
auditable half — it proves the ledger was not edited. The reproducible half was implemented in
`core.Replay` and `core.DecisionsEquivalent`, carefully — an explicit allowlist of compared fields,
with a doc comment explaining that a denylist would let a newly added field weaken replay silently —
and **had no caller**. No command exposed it. Nobody had ever replayed a decision.

Fifth instance of the shape, and the one closest to the product's central promise.

### The command is narrower than it first appears, and that is the design

The ledger stores **no content** (D10/D29). That is the privacy property the product is built
around, and it is not being relaxed to make replay convenient. So replay cannot be "re-run decision
45": the operator supplies the event, from wherever they still have it, and the question answered is

> given THIS input, does the policy still produce what was recorded?

It does **not** establish that the input is what the original decision saw. A file event replays
against the file's current bytes. Every divergence report therefore names both causes — the policy
changed, or the input changed — because an operator who reverts a policy over a file somebody edited
has been misled by a report that was technically accurate. Both the success and the failure report
state what was not established; a bare "REPRODUCED" invites the stronger reading.

Four outcomes, four exit codes: reproduced, diverged, no such entry, ambiguous id. Collapsing "no
such decision" into "diverged" would let a typo in an event id fail a policy gate as though the
policy had regressed.

### The first version failed against a decision the engine had just written

Exit 3, and the only differing field was `policy_id`: recorded as `openshield.default@phase1-1`,
replayed as `openshield.composite@default`. **Identical rules, different identity, decided by how the
stage was constructed.** The CLI had called `policy.NewComposite` directly with an empty pack list;
composing nothing with the default is still labelled composite.

The impact query said HIGH risk on `NewComposite` — two binaries reach it — and reading the caller
showed the library was already right: `SelectFromEnv` returns `NewDefault` when no packs and no
custom module are set, which is why the engine stamped `default`. **The bug was in the new code, not
the old.** The fix was to use the same selector the engine uses, reading the same
`OPENSHIELD_POLICY_*` environment, so the CLI cannot drift from what the engine loaded — which is the
only way this command's answer means anything.

Worth keeping: the blast-radius warning was right to fire and wrong to act on. Reading the impacted
caller was what turned a HIGH-risk edit into a three-line fix in code written ten minutes earlier.

### The mutation killed one test and not the other, honestly

Disabling the action comparison fails the **unit** test, which isolates that field. The
**integration** scenario still passes, because its divergence changes the input, which changes the
`reason` as well as the action — so `reason` catches it. That is defence in depth rather than a
vacuous test, and the division is deliberate: the unit tests pin field-level comparison, the
integration scenario pins the end-to-end wiring against a decision the engine really wrote. Recording
it because a surviving mutation always deserves an explanation, and "it is covered elsewhere" is only
acceptable when the elsewhere is named.


## Round 29 (D345): the dead function was the correct one

The sweep that found the SMTP connector returned a handful of other symbols with no non-test caller,
and the plan was a cleanup: delete what is superseded, keep what is not. Four of them were what they
looked like — `core.Replay` (now superseded by `cli.Replay`, which dispatches, compares AND reports),
`gateway.SignUpdate` (byte-identical to `controlplane.signRiskUpdate`), `classify.NewWithEDM` and
`NewWithIDM` (convenience constructors for `New()` + `AddEDM()`), and `enforcers/process.DenyEnforcer`
(a second implementation of `DENY_EXEC`, which `execguard` really enforces at the kernel).

`classify.BuildEDMIndex` was not. **It was the correct implementation, and the live path was the
broken one.**

### The requirement was satisfied by a function nobody called

`exact-data-matching` requires, in as many words:

> **WHEN** a dataset contains short/common tokens alongside distinctive values
> **THEN** the builder indexes the distinctive values and skips the low-entropy ones

`BuildEDMIndex` applies `distinctiveEDM`, skips values that are too short or read as dictionary
words, and returns a skipped count. Unit-tested. No caller.

`openshield-dlp-index edm` — the tool an operator actually runs — built the index itself with
`NewEDMIndex` and an unfiltered `for … idx.Add(v)`. The `record` builder immediately below it uses
`BuildRecordIndex` and even fatals when nothing distinctive survives, which is what makes the EDM
path's omission read as an oversight rather than a decision.

### Why this was worse than a detection gap

Indexing non-distinctive values does not weaken detection — it **manufactures false positives**. A
`city` column, a `status` column, a column of first names, and every document containing "active" or
"Smith" matches as carrying protected customer data. Observe-only that is noise; with enforcement on
it is blocked legitimate traffic from a control behaving exactly as configured. That is how a DLP
deployment gets switched off, which is a worse outcome than the detection the feature exists to
provide.

The mutation shows it rather than argues it: restore the unfiltered loop and the sentence *"the
ticket is active and assigned to Smith in london; status open"* raises a DLP alert.

### The lesson that generalises

A test at the library level can satisfy a requirement while the shipped path violates it. The
unit test for `BuildEDMIndex` passed on every run, and it was testing a function that no binary
called. **Coverage of a requirement is not coverage of the path that ships** — which is the eighth
way a green test can mean nothing, and the first one this audit has found where the correct code
existed all along.

It also inverts the assumption the sweep started from. "No caller" was being read as "dead, delete
it". Here it meant "the shipped path is doing something else, find out what".


## Round 30 (D346): three of the four were dead, and the fourth was a correction to make

D345 removed the EDM builder's defect and stated that the other four no-caller symbols "were what
they looked like". Applying D345's own lesson to that sentence — check what the shipped path does
before believing "no caller" means "dead" — found one of the four was wrong.

**`enforcers/process.DenyEnforcer` is deliberately not registered, and the engine says so.** The
comment beside the registration explains that `DENY_EXEC` is answered by the WATCHDOG's inline path —
`execguard.Decider` maps it to a kernel `FAN_DENY`, reusing the fail-open budget — and that
registering the enforcer as well would **double the deny**, once via the enforcer and once via the
kernel answer. It is kept for the alternate async flow-enforcer model, where an engine dispatches exec
events without holding the permission fd.

So it is not superseded; it is a documented alternative to a path that is deliberately not taken. It
stays, and D345's description of it is corrected here rather than left to read as a plan nobody
executed.

### The three that were dead are gone

- **`core.Replay`** — dispatch-and-compare, which `cli.Replay` now does with reporting: the
  distinction between a divergence, an unrecorded event and an ambiguous one, and the warning that a
  divergence can mean the input changed. Two entry points differing only in whether they explain
  themselves is the duplicate hazard this round exists to remove. `DecisionsEquivalent` — the actual
  contract — stays, and is what the CLI calls.
- **`gateway.SignUpdate`** — byte-identical to `controlplane.signRiskUpdate`, which `PublishRisk`
  really uses. The gateway only VERIFIES. Two producers of one envelope is the hazard that matters:
  change one to sign a domain-separated payload and the other keeps emitting the old shape while the
  verifier accepts whichever it was compiled against. The tests that need to construct an envelope
  now use a helper that lives with the tests, so the duplication is visibly a test concern.
- **`classify.NewWithEDM` / `NewWithIDM`** — `New()` + `AddEDM()` is what the worker does. After
  D345, an unused constructor sitting beside the used path is precisely the confusion worth deleting.

### What the round is actually for

Nothing here changes behaviour, and that is the point: the value is in the count of ways a future
reader can take the wrong path. D345 happened because two builders sat side by side and the shipped
tool used the wrong one. Every duplicate removed is one fewer chance to repeat it — and every
duplicate KEPT, like `DenyEnforcer`, now has to say why in the code rather than in a reviewer's head.


## Round 31 (D347): the exec source read the file once and stopped

`internal/connectors/execaudit` measured at zero integration coverage. Driving it found the same
shape again, in the endpoint's process-visibility source.

`OPENSHIELD_EXEC_AUDIT_LOG` is described as "auditd log the exec connector reads". Point it at
`/var/log/audit/audit.log` and the engine `os.Open`s it, the scanner's `for sc.Scan()` drains it,
reaches EOF, and returns **nil** — a successful return. The goroutine exits. Every execution recorded
BEFORE startup is ingested; **none after it, ever**, and nothing is logged, because nothing failed.
The startup line says `exec connector ENABLED` either way.

So HIPS process detection was a control that reported itself on, processed a backlog once, and was
inert for the life of the process. "No suspicious executions" and "no executions were looked at" read
identically.

The engine's own comment named the intended sources — "a tailed audit log, a fifo, or the audit
socket" — so the deployment shape was understood. The setting's description does not say it and the
code did not enforce it, which is the whole distance between a design and a product.

### A reader that does not end, not a loop that restarts

The scanner's contract is unchanged: give it an `io.Reader`, it pairs SYSCALL+EXECVE and emits.
Teaching that loop about log rotation would put filesystem logic inside a record parser. Instead the
engine supplies a reader that waits on EOF instead of returning it, resumes from zero when the file is
shorter than what was consumed (truncation), and reopens when the path names a different inode
(rotation). A fifo is left alone — it already blocks correctly while a writer holds it open, and
wrapping it would add a poll to a path that is already right.

Both rotation cases are best-effort and can lose records written to the old file between the last read
and the rename. That bound is the filesystem's; it is named rather than claimed away.

### And an ended source is now loud

`execSource` returning nil meant both "the context was cancelled" and "the stream ended". One is a
clean shutdown, the other is the endpoint silently ceasing to report executions while the process
keeps running. They are now distinguished: shutdown stays quiet, an end-of-source under a running
engine is a WARN naming what was lost.

### The test had to be written the hard way round

The records are appended AFTER the engine is running, against a file that is EMPTY at startup — the
exact state in which the old code gave up. Writing them first would have passed against the broken
behaviour, which is precisely how a defect survives a fully unit-tested parser: the parser was never
the problem.

### The mutation failed to compile, again

The first mutant removed the follower and left its import unused, so the build failed and the test
"failed" for the wrong reason — which is indistinguishable from a successful mutation unless you check
`go build` first. Same trap as D338, caught the same way. The compiling mutant, which keeps the import
live and simply does not install the follower, times out waiting for the appended execution.


## Round 32 (D348): twenty counters, eight of them unreadable

`internal/connectors/limiter` measured at zero integration coverage. Chasing it found something
larger than the limiter: **every listener counts what it discarded, and almost nothing reads those
counters.**

`RateLimited()` — zero non-test readers, across the DNS listener, the syslog datagram listener and the
syslog stream listener. `Oversize()` — zero. `Refused()` — zero. `Dropped()` — exactly one.

Then the control plane: 20 declared `atomic.Int64` counters, **8 never rendered on `/metrics`** — the
entire external-log ingest path (CEF, CloudTrail, WEF), entity-graph resolve failures, and retention
record failures. Every one written with a comment explaining that it exists so a discard is not
silent. `CEFDropped`'s says the drop is "COUNTED … never silent". `EntityResolveFailures` says a
non-zero value is "observable rather than silent".

None of them were observable.

### A comment that asserted the opposite of the truth

Beside the CEF counters:

> The names are kept because they are exposed on /metrics and renaming them would break every
> dashboard built on them

They were not exposed. No dashboard could have been built on them. A maintainer reading that would
decline a rename to protect users who could not exist. The comment is now corrected in place rather
than rewritten — the *reason* it gave for keeping the names is still right, and the record of it
having been false is worth more than a tidy sentence.

### The guard is the fix; the eight are the symptom

They did not go missing at once. They accumulated one at a time, each added by someone who reasonably
assumed the metrics surface already covered them — and the next one would too. So a test reflects over
the `Server` struct, finds every exported `atomic.Int64`, and fails the build when one is not rendered.

Reflection rather than a hand-maintained list, deliberately: a list is a second thing to forget, and
forgetting it looks exactly like the bug being fixed. Mutation-verified by deleting one metric line —
the guard fails and names `WEFDropped`.

### Absent is not zero

A listener's counters are published only while it runs. Reporting `rate_limited=0` for a listener that
does not exist is a *different claim* from not running one, and a dashboard alerting on `== 0` cannot
tell them apart. The integration scenario asserts both directions, because the absence assertion alone
is satisfied by a counter that is never emitted under any condition.

### The engine reports rather than exposes, and only on movement

The engine has no HTTP surface, and giving it one is a decision about opening a port on every endpoint
— not a side effect of adding a counter. So it logs, and only when a counter has increased: a
periodic line that fires unconditionally becomes noise, gets filtered, and turns a signal into a
silence with extra steps. A healthy listener is silent; one that starts discarding says so every
interval until it stops. The asymmetry is deliberate — a missed report is an unnoticed visibility gap,
a repeated one is a duplicated line.


## Round 33 (D349): the provisioning tool's keys had never been given to a consumer

`openshield-provision risk-keygen` had never been invoked by the suite. Every scenario touching the
SEC-1 risk path minted its keypair in Go, so the bytes the shipped tool actually writes had never been
handed to either consumer — the server that signs risk, or the gateway that verifies it.

That is the D339 shape: producer and consumer agree in tests that construct their own material, and
nobody checks the artefact an operator is told to create. Here the failure would be quiet in the worst
way: the gateway's degraded mode for absent risk is to apply none, so continuous verification (D89)
would evaluate every subject as unremarkable, forever, with the access proxy behaving exactly as
designed.

The scenario provisions with the real tool, points the gateway at `risk-pub`, publishes a signed
update with `risk-priv`, and asserts on an **access decision**: the same request succeeds, then is
refused. Nothing about the request changes but the risk the gateway holds.

`posture-keygen` was the other uncovered subcommand and is left alone deliberately — it is the
superseded shared-key form, kept so existing scripts do not break, and it says so loudly on every run.
Covering it would be testing a deprecation notice.

### Three wrong turns, each one informative

**The catalog resolves by HOST.** Addressing the proxy directly with the service in the path returns
404. A client behind DNS names the service and the dial goes to the proxy, and the test has to have
that shape or it is not exercising the catalog at all.

**Reading the subject from the ledger did not work**, and the reason is worth keeping: access
decisions were not landing in `audit_entries` with a subject within the window the test waited. Rather
than widen the wait until it passed — which would have made the test slow and its premise unexamined —
the subject now comes from `pseudonym.Of`, the same canonicaliser the gateway uses.

**That is using a shared contract, not reimplementing one.** The distinction matters: a test that
re-derived the mapping would agree with itself whatever the gateway did. Calling the same function
means this scenario tests the RISK path and explicitly not the identity mapping, which has its own
tests. Said in the test rather than left for a reader to work out.

### The mutation is the one that matters

Verified risk that is stored and never reaches the policy input: the update is signed correctly,
accepted, recorded — and the access decision does not change. The request returns 200 and the test
fails naming the subject. That is precisely the silent degrade this scenario exists to catch, and it
is indistinguishable from a healthy deployment from every angle except an access decision.


## Round 34 (D350): a decision crossing the trust boundary was never contract-checked

`core.ValidateDecision` checks the things that matter about a Decision — the action is in the closed
set, confidence is in range, a policy id and version identify what produced it — and its own comment
states the stakes: "An unknown action is a signal that the producer and consumer disagree about the
contract, which is a security event, not a reason to permit the operation."

It had no caller. Decisions arriving as fleet telemetry were unmarshalled, stored, and projected into
`unified_alerts` — the stream correlation, incidents and entity risk are built on — unchecked.

### What that permitted

Signature verification runs first (D44), so this is not open injection. It is what an **enrolled**
agent could do: compromised, key-leaked, or merely version-skewed.

`severityForDecision` calls `Severity(confidence)`, which returns CRITICAL for anything at or above
its floor, and confidence was never range-checked on ingest. A decision carrying `confidence: 999`
became a CRITICAL alert. **An agent could manufacture critical alerts at will**, and the engine's own
producer clamps confidence below 1.0 (D4) — but that clamp is on the producing side, and a telemetry
payload never passes through it.

An action outside the enum fared no better: `alertableAction` admits anything that is not UNSPECIFIED
and not ALLOW, and `enforcementAction` — a switch over the known set — returns false for it, grading
the alert as if nothing had been enforced. The comment on that switch says a total mapping is "exactly
what makes this mapping safe: a compromised control plane cannot invent an action whose severity we
failed to consider". True of the control plane. The telemetry path was never held to it.

### Two things the implementation got wrong first, and how they were caught

**Ordering.** Validating before the alertable check flagged every ALLOW, because a legitimate ALLOW
can carry no policy identity in a fixture and, more importantly, because a non-alertable decision is
not projected anyway — the counter would have reported traffic rather than attacks. The check now runs
after, so only decisions that would become alerts are contract-checked.

**Requiring confidence to be PRESENT.** proto3 cannot distinguish an absent double from 0.0, so the
first version probed the wire form and refused absence. Checking the producing side before believing
that was right: `confidenceFrom` returns 0.0 for an alertable decision whenever the policy sets no
confidence over an event with no classification hits — **and the NIPS-3 DNS-tunnel rule shipped in
D341 is exactly that shape.** Enforcing presence would have refused the alerts of a feature shipped
nine rounds earlier. Absence grades LOW, which is not a forgery vector; the vector is out-of-range,
and that is still refused.

### The existing fixture could not have occurred

Two tests failed on the new check because their Decision fixture omitted policy identity — and both
real producers (the policy stage, and the ledger reading one back) always set it. The fixture was
standing in for agent telemetry and constructing a shape no producer in the system emits. That is mild
evidence of the gap itself: a fixture drifts from reality most easily where nothing validates it.

### Why refused decisions are still stored

Two silences were available. Dropping the telemetry keeps the alert stream clean and destroys the
evidence that a malformed decision arrived — the signal an investigator most wants after learning an
agent was compromised. Projecting it keeps the evidence and corrupts the stream. So: stored, not
projected, counted, and logged with which check failed and which agent sent it — because "a decision
was refused" is not actionable and "this agent is sending actions this build does not know" is.

The counter is an ordinary `atomic.Int64` on the Server, which means **D348's guard forced it onto
`/metrics`**. That is the first time one of this audit's guards has caught the next round's work.


## Round 35 (D351): a capability that no operator could start

`internal/ztna` is the endpoint half of Zero-Trust access. It brokers an application's traffic to the
access proxy while presenting the DEVICE's certificate, refuses to start without an identity, binds
loopback only, never falls back to a direct connection when the broker refuses, and does not follow
redirects off the authorized path. Four tests drive it against a real access proxy.

**No binary built it, and no settings existed.** An operator had no way to run it, however the
deployment was configured. The roadmap counts ZT-4 as shipped; the README had to be corrected in D343
to say the endpoint client was "built and not yet shipped as a binary" — a sentence that existed only
because of this gap, and which this round deletes.

Second instance of a whole capability being unreachable, after the SMTP connector (D342), and found
the same way.

### The binary is thin, deliberately

Everything that decides anything stays in the library, because that is where the four tests reach. The
binary reads configuration, builds TLS material, and calls `ListenAndServe`. A binary that
re-implemented the loopback check or the identity refusal would have moved those decisions out from
under their tests while appearing to strengthen them.

Every configuration problem is fatal. A ZTNA client that started without a device certificate would
forward traffic unauthenticated while looking like protection — worse than not running, because the
application keeps working and nobody learns the identity was never presented.

### Three guards caught the work, which is the point of having them

Adding the binary failed `TestEveryBinaryIsCovered` immediately: five `OPENSHIELD_*` variables read
with no declared field set. There are **two** such registries — one in `scope_wiring_test.go`, one in
`config_test.go` — and updating only the first left the second failing. Then
`TestRunbookDocumentsExactlyTheShippedBinaries` refused it for a third reason: a binary ships and the
runbook does not name it, so "an operator meets a component the documentation does not mention".

None of the three was written for this change. Between them they made it impossible to add a binary
that is unconfigurable, undeclared, or undocumented — which is precisely the class of gap this audit
has spent thirty-five rounds finding by hand.

### The mutation is unusually clean

Removing the device certificate from the client's TLS config produces:

    502 "ztna: broker unreachable: … remote error: tls: certificate required"

The broker refuses the connection outright. That is the property stated as plainly as it can be: the
request is authorized by the DEVICE's identity, and without it there is no request at all.

### The limit is now stated where it will be read

The library's doc comment says it brokers access and does not prevent bypass. A README is read once;
an application that later takes a direct route to the internal network is announced by nothing. So the
process says it on every start, alongside the HTTP(S)-only bound and the fact that it is not an
enrolment tool — the same discipline as the SMTP capture listener and the plaintext syslog stream.


## Round 36 (D352): B2 — the inline file-open gate, and the design that had to change first

`internal/agent/prefilter` was the synchronous tier of two-tier inline prevention: complete, tested,
and answering events nothing produced. The README said so honestly — inline blocking of a file open
"remains designed and not wired". This wires it.

### Reading the design found two defects before any code

`Decider.DecidePartial` opened `e.Path` to read its prefix. Under the mark, that open raises **another**
permission event, which the same gate must answer, which opens the file again — a deadlock inside a
window that is **uninterruptible**, so the machine does not recover. The watchdog exempts only
`SelfPID`, which does not help: the opener is a different process.

And opening by path is a **TOCTOU hole** — the event names an inode, the path may name a different file
by then, so the gate would authorize what it inspected while the kernel releases what it did not. That
one survives any fix to the deadlock.

**The resolution is structural.** The agent reads the bounded prefix from the descriptor the kernel
already handed it. No new open happens anywhere, so no second event can be raised; and the descriptor
refers to the inode being decided about, so there is nothing to swap. The alternative — exempting the
engine's PID — avoids the deadlock by bookkeeping that goes stale on restart or PID reuse, and the
failure mode of getting it wrong is an unrecoverable host.

That is why this IPC carries content when the exec bridge's doc ends "Never content". The direction is
what keeps it safe: content travels PRIVILEGED → UNPRIVILEGED, so the agent WRITES bytes it read and
decodes only a fixed-width verdict frame. The dangerous operation is unchanged, and D13 holds — the
agent holds bytes, only the worker parses them.

### The kernel answered the question the exec gate got wrong

D224 recorded that a directory inode mark does **not** deliver `FAN_OPEN_EXEC_PERM` for files executed
within it, which is why execmon marks the mount. Opens are different, and this was measured rather than
assumed: a directory mark with `FAN_EVENT_ON_CHILD` **does** deliver opens of the files inside.

That difference is what makes a mount mark refusable here. Marking a mount for opens would route every
open on the host — the package manager's, the shell's, the engine's own — through a permission window
that blocks its caller uninterruptibly. A mount-wide scope is refused, and so is naming a regular file,
because that is almost always a mistake an operator meant as "this directory".

### Verified in the order that keeps a host alive

ALLOW first, then fail-open, then scope refusal, then DENY — every command under `sudo -n timeout N`,
in fresh temp directories, with a short budget. A gate broken in the blocking direction shows up in the
first test bounded by a timeout rather than in a wedged machine. This host was bricked twice earlier in
the same session by unbounded root processes in permission windows; the ordering is not ceremony.

All four pass on kernel 6.8. Both mutations fail on the same hardware: a BLOCK that no longer denies
lets the opener through, and a prefix that is never read leaves the decider with `""` — a content gate
deciding on nothing.

### What is NOT done, named rather than dropped

The budget measurement. The gate is correct and fails open; what is not established is the p99 cost of
a decided open, which is the number that decides whether this is deployable on a busy directory. The
exec gate has that measurement (p50 41µs, p99 987µs against a 200ms window, D301) and this one will
need its own before it is recommended anywhere real.


## Round 37 (D353): measuring B2 found the knob it was missing

D352 landed the file-open gate and named what was not done: the budget measurement. This is it, and
measuring changed the product rather than merely documenting it.

**p50 26ms, p99 29ms, against a 150ms window.** It fits — with roughly five times the headroom — so the
gate delivers verdicts rather than silently degrading to fail-open, which is the correctness property
the number exists to establish.

But fitting the budget is not the same as being deployable, and the exec gate's number makes the
contrast plain: **41µs there, 26ms here.** Three orders of magnitude, because an exec decision
classifies a path and an open decision classifies 64 KiB of content.

### The curve is what an operator needs, not the ceiling

| prefix | p50 |
|---|---|
| 4 KiB | 1.5 ms |
| 16 KiB | 6.4 ms |
| 64 KiB | 25.9 ms |

Linear, at about 0.4ms per KiB. That is fine for a directory of sensitive documents opened
occasionally, and ruinous for a source tree — and every open in those directories waits that long,
uninterruptibly.

### And the knob did not exist

The prefix size was hard-coded to the ceiling. An operator with a busier directory had only the choice
between a slow directory and no gate at all, which is not a choice anyone makes in favour of the gate.
`OPENSHIELD_OPEN_PREFIX_BYTES` now exists, the startup line reports the resulting cost per open, and
the runbook carries the table above with the blunt advice not to point this at a build directory.

**This is the argument for measuring rather than declaring done.** The gate was correct, tested on a
live kernel, mutation-verified, and shipped with a missing setting that would have made it unusable
wherever anyone actually wanted it. Nothing about that was visible from the code; it took a number.

The measurement is a build gate, like the exec gate's, and for the same reason: an over-budget verdict
does not make the product slow, it makes the gate stop happening while every log line still reports it
as active.


## Round 38 (D354): two guards refused B2, and the second one was right about something I had reasoned past

CI failed four B2 commits on two separate guards, both written earlier for defects that had already
happened once.

### The macOS socket-address guard caught its own author

Six unix socket paths in the new tests were built from `t.TempDir()`, which embeds the TEST NAME.
`sockaddr_un.sun_path` is 104 bytes on macOS and the kernel refuses rather than truncates, reported as
"bind: invalid argument" — a message naming neither the length nor the cause.

That guard exists because this exact bug cost over a day of red CI: a descriptive test name breaks the
bind and a short one hides it, so the constraint was enforced only by a platform nobody here develops
on. It caught the person who wrote it writing the same bug again, which is the best argument for
writing it.

### The D13 boundary check caught a real design error

`FAIL: the privileged agent depends on parsers it must never hold.`

The `openipc` package is imported by the PRIVILEGED agent for its Client — so everything it references
is linked into a binary holding CAP_SYS_ADMIN. Its Server used `*corev1.Decision`, dragging protobuf
in; and once that was removed, `log/slog` dragged in `encoding/json`. A wire-format decoder in the
privileged process is precisely what splitting the binaries exists to prevent.

**This is worth recording because I had reasoned carefully about D13 and still got it wrong.** The
design notes argue at length that the agent may HOLD attacker bytes without PARSING them, and that
argument is correct — reading a bounded prefix into a buffer interprets nothing. But D13's protection
is not only about what the code does; it is about what is LINKED IN, because a parser in the address
space is exploitable whether or not this code calls it. The reasoning was sound and aimed at the wrong
property.

`execipc` had already reached the shapes that avoid this — an `Evaluate func` returning a Verdict
rather than an interface returning a Decision, and a `Logf func` rather than a `*slog.Logger` — and
those looked like style choices until the check explained them. They are the boundary, expressed in a
signature.

So the action→verdict mapping moved to the engine, where corev1 already lives, and the server logs
through a func. The mapping is still explicit — only BLOCK and QUARANTINE_LOCAL deny, never "anything
that is not ALLOW" — it just lives in the right process now.

### And it still works

All four VM scenarios re-run and pass on kernel 6.8 after the refactor. A boundary fix that quietly
broke the thing it was protecting would have been the worse outcome, and the only way to know is to
run it again on the hardware.

### What this says about the local loop

`make quick` and targeted package tests pass on Linux for all of it. The macOS limit is invisible here
by construction, and the agent-dependency check is not in the fast loop. CI is the tree-wide check
precisely because it runs what the local loop cannot.


## Round 39 (D355): CI ate the headroom, and the default was wrong

The latency test failed on CI under `-race`: *decision 38 failed: stage "prefilter-classify": context
deadline exceeded.* Locally the same measurement is p99 29ms against a 150ms window.

Two conclusions, and the second matters more.

**A latency measurement under the race detector measures the race detector.** It instruments every
memory access at several times the cost of the real work, so the number is neither production's nor a
stable threshold. The test now skips under `-race` — and skips rather than widening its budget,
because a budget loose enough to pass under instrumentation would no longer fail when the real path
regressed, which is the only thing the test is for.

**But the failure was also telling the truth about the default.** At the 64 KiB ceiling the margin is
about five times. That sounds ample and is not: the race detector is several times slower than
production and no slower than a loaded host, and an over-budget verdict does not arrive late — it
**fails open silently** while the gate still reports itself active. Five times is not a margin for a
control whose failure is invisible.

So the default is now 16 KiB (~6ms, roughly 25x), with the ceiling available to an operator who wants
more inline depth on a quiet directory and now knows what it costs. The runbook says the default is
deliberately not the ceiling and why.

**This is the third time in two rounds that CI found something the local loop structurally could not**
— the macOS address limit, the agent's linked-in parsers, and now a timing margin that only shows on a
slower machine. Each was invisible here by construction rather than by oversight.


## Round 40 (D356): the per-event budget was not a per-process bound

D355 ended by naming what the measurement could not answer: the gate had never run under concurrent
load. It turns out the single-decision number was hiding a structural problem.

**The watchdog's budget starts when it DEQUEUES an event, not when the kernel blocked the process.**
Both gates answered events one at a time, so the Nth opener waited N × the decision cost while every
answer still read as inside budget. Measured on a live kernel: twelve concurrent opens at 25ms each
took **306ms**, exactly serial.

The exec gate has the identical loop and does not need fixing, and the reason is scale rather than
luck. An exec decision is ~41µs, so fifty concurrent execs queue for 2ms — invisible. An open decision
is ~6ms, so fifty queue for 300ms. **The same structure is safe at one scale and not at the other**,
which is why copying a proven shape is not the same as proving it.

### Two changes, and they had to be made together

Handling events concurrently alone would have made it worse: the IPC client held ONE connection, and
the wire is one request and one response per exchange, so two goroutines would interleave writes and
read each other's answers. The request-id check catches that and fails open — correct, and useless,
because the gate would then allow everything under exactly the load it most needs to work.

So the client got a connection pool and the producer a bounded worker set, sized the same. They are the
same queue seen from either end, and a producer running ahead of the pool would only move the waiting
from one side of the socket to the other.

**Bounded, not unbounded**: ten thousand simultaneous opens would otherwise cost ten thousand
goroutines and connections in a process holding CAP_SYS_ADMIN. When every slot is busy the producer
blocks, the kernel's queue absorbs it, and an event that waits too long is answered by the watchdog's
budget as a fail-open — the correct answer for a gate that cannot keep up.

306ms → 53ms, and all five VM scenarios still pass.

### The lesson is about what a benchmark measures

A single-decision latency test on an idle machine says the decision fits the window. It cannot say the
gate does, because it never asks two questions at once — and the thing that breaks is not the decision
but the queue in front of it. The number was accurate and the conclusion drawn from it was wrong.


## Round 41 (D357): the concurrency stopped at the worker's mutex

D356's measurement — 306ms → 53ms for twelve concurrent opens — used a **sleeping stub** as the
decider. It proved the producer and the socket no longer serialise. It said nothing about the
classification behind them, and I reported the improvement without that caveat.

`privileged.Worker.Classify` holds a mutex for the whole request. The engine ran a single worker. So
every concurrent decision queued at that mutex, and the gate's concurrency bought nothing for real
content.

Measured rather than reasoned: **eight concurrent decisions take 54ms against one worker and 11ms
against a pool of eight.**

The gateway already used `privileged.Pool` for exactly this reason; the engine used `StartWorker`,
which is correct for the async path — file events arrive one at a time from the watcher — and wrong
the moment an inline gate is served from the same process.

### The default chooses, rather than warning

One worker normally; the gate's in-flight bound when the gate is enabled. `OPENSHIELD_WORKER_POOL`
overrides it.

Automatic rather than a warning, deliberately. An operator who enables the gate and misses a log line
would get silently serialised decisions — which is the exact failure this area keeps producing, and a
warning is a fix that only works on people who read warnings.

### The pattern across three rounds

D355: the single-decision number was fine and the default it implied was wrong.
D356: the decision fitted the window and the queue in front of it did not.
D357: the queue was fixed and the resource behind it was still serial.

Each measurement was accurate and each conclusion drawn from it was too narrow — because a bound is
only meaningful against the specific thing being measured, and the next bottleneck is always
downstream of where you stopped looking. The stub that made D356's measurement clean is what hid
D357's.


## Round 42 (D358): the gate refused opens and left no evidence

D357 ended by naming the async tier as unverified. Looking at it found something worse than an
unverified half: **a gated open, including a DENIED one, produced no ledger row at all.**

`Decider.DecidePartial` deliberately set no `OnOutcome`, with a comment giving the reason: "the
synchronous tier does not write the ledger — the async engine owns the durable audit row (D16)." That
is a correct division of labour, and for the inline file-open gate the async engine **does not exist**.
The gate's events reach no pipeline; `PreFilter` and its `AsyncSubmitter` seam are not wired, because
the engine's server calls `DecideBytes` directly.

So the platform whose thesis is that every decision is explainable, reproducible and cryptographically
auditable was refusing file opens and writing nothing down. The one decision an investigator would most
want to review — an inline refusal — was the one that was never recorded.

### Handed out, not written, inside the window

The outcome is passed to the caller inside the permission window and QUEUED; a goroutine appends. The
ledger write must not sit inside the window — the watchdog makes exactly this point about its own
fail-open audit, and for the same reason: a slow append would hold a blocked process for the duration
of a database write.

A full queue **drops and counts**, reported at shutdown. Holding a process in an uninterruptible window
to wait for a database is a worse failure than a missing row, and a silent drop would be worse than
either.

### What is still not done, and why it is harder than it looks

The async tier — classifying the WHOLE file rather than the prefix — remains unwired, and the reason is
the same recursion that shaped the whole design. The async classification would open the file; that
open falls under the mark; the gate must answer it; and if that event is also submitted asynchronously,
it recurses forever. Solving it needs the engine's PID exempted from the gate, which is the bookkeeping
answer D352 rejected because its failure mode is an unrecoverable host.

So the honest position: the gate decides from a prefix, records that decision as evidence, and does NOT
deepen the classification afterwards. The design's second tier assumes an exemption that does not exist,
and the README's claim about the async tier should be read as describing the file-watcher path rather
than the gate.


## Round 43 (D359): the engine's half of the gate, against a real ledger

B2's producer needs CAP_SYS_ADMIN and is verified on the VM. The ENGINE's half needs neither — it
answers verdicts on a socket from the real pipeline — and until now was covered only by unit tests with
a stubbed decider. That is the half a deployment actually runs.

The scenario drives the socket with a hand-built frame and asserts on POSTGRES: ordinary content
allowed, a checksum-backed CPF refused, both decisions in the ledger, and the ledger content-free.

**The frame is hand-rolled rather than imported, deliberately.** Encoding with the same code the engine
decodes with would agree with itself whatever either does. A frame built from the format as DOCUMENTED
catches a wire change both sides adopted without anyone noticing the compatibility break.

It also asserts the engine started a WORKER POOL — D357's finding, where a single worker silently
serialises every classification and undoes the gate's concurrency.

### The mutation failed to compile, and my check missed it

The first mutant produced a syntax error, and the shell chain (`go build … | head -3 && echo
MUTANT_COMPILES`) reported success because `head` exited zero. The test then "failed" on a broken
build, which is indistinguishable from a successful mutation.

**Third time this session** — D338, D347, now here — and the first two were caught by re-reading the
output. This one was caught only because the failure message named a build error rather than an
assertion. The lesson has upgraded from "check `go build` first" to "the check itself must not be able
to lie": piping a compiler through `head` discards its exit status.

The compiling mutant — the seam installed but discarding every outcome, which is exactly D358's
behaviour — times out waiting for rows that never arrive.


## Round 44 (D360): the second tier, and a rejected option that was never necessary

Round 42 closed with the async tier "still unwired", and gave a reason:

> Solving it needs the engine's PID exempted from the gate, which is the bookkeeping answer D352
> rejected because its failure mode is an unrecoverable host.

**That reason was wrong**, and it is worth saying why rather than quietly shipping the fix. The
recursion is real — the async classification opens the file, that open falls under the mark, the gate
answers it, and answering submits again — but breaking it does not require knowing which processes are
ours. It requires knowing which **paths** are already being classified. Suppress on the path and the
classification's own open is still decided, simply not resubmitted; the loop terminates after one
iteration, and no exemption exists to go stale.

The mistake has a shape worth naming: **I inferred the solution space from the failure.** The failure
was "our own process's open comes back to us", so the fix had to be about identifying our own process.
It did not. The question the code actually has to answer is not *who is opening this* but *have I
already asked for this to be classified*.

### The seam was there the whole time

`prefilter.PreFilter` has carried an `AsyncSubmitter` interface since Phase B — documented, typed, and
called on every evaluation. It was never given an implementation by the gate's wiring, so the interface
was satisfied by `nil` and the call was skipped. The eighth entry in the list below applies: coverage of
a requirement is not coverage of the path that ships. `AsyncSubmitter` was covered. The engine's gate
never used it.

### A TTL alone would not have worked, and the reason is timing

The obvious suppressor is a map from path to expiry. It is wrong in a way that is invisible in a fast
test: if the entry expires **before** the classification's own open arrives, that open resubmits, and
the cycle restarts every TTL — forever, more slowly than a tight loop, which makes it harder to notice
rather than less harmful.

So an entry is *pending* from submission until the classification reports, and a pending entry does not
expire. The suppression structurally covers the gap between submitting and the open that submission
causes, however long the queue is. `Done` is load-bearing, not bookkeeping — and mutating `live()` back
to a plain TTL fails the unit test that says so.

### The bound refuses rather than evicts

The cache is keyed on paths, which are whatever the host opens, so it needs a ceiling. At the ceiling it
**declines new submissions** rather than evicting a live entry. Evicting one would re-arm the cycle for
the evicted path — the mechanism added to bound memory would restore the loop it was added alongside.
Declining costs a full-file classification, which is a detection gap, and it is counted and reported at
shutdown. Given a gap or a wedged host, take the gap and say so.

### Reservation is not capacity

The gate now runs its **own** worker pool. A larger shared pool was considered and is not equivalent:
the nested decision is caused by the very async work that would otherwise take the last worker, so
under load the gate times out and fails open exactly when it is busiest. A bigger pool makes that less
likely; reservation makes it impossible. Those are different properties and only one of them is what
the failure needs.

### The VM test asserts termination, and the mutation is capped

A design that recurses does not produce a red test. It produces a host that stops — every opener sits
in an uninterruptible permission window. So the VM scenario hard-caps resubmission at twenty, far above
the one a correct implementation reaches and far below what hurts.

That cap is what makes the mutation runnable rather than a thing to reason about and hope. With the
dedupe removed: **21 gate questions, 21 classifications, cap fired, FAIL**. With it: **2 questions, 1
classification.** The second question is the classifier's own open — decided, as it must be, and not
resubmitted.

### A guard caught it again

`TestEndpointEnvVarsAreDeclared` refused the three new settings until they were declared with their
reasoning. The config schema is where an operator meets this feature, and three undeclared knobs would
have shipped as folklore.


## Round 45 (D362): fuzzing the privileged decoders, and a suite that had never run on 32-bit

The roadmap named fuzzing the untrusted parsers as a gap a reviewer checks before betting on the
platform. Measured before starting: **one** fuzz target in the tree, no corpus, and no `-fuzz` token in
the Makefile or either workflow — in a project whose entire privilege split is justified by parsers
being dangerous.

### The stated reason was wrong, and inheriting it would have been dishonest

The roadmap said *"the D13 threat — ClamAV-CVE-class RCE"*. Go is memory-safe; a heap overflow reaching
code execution is ruled out by the language, not by testing for it. What these decoders can actually do
is panic, allocate unboundedly, or fail to advance — and the reason that matters here is what the
process is, not what the language allows. The agent answers BLOCKING permission events, so while it is
dead or spinning every process opening a watched file sits in an uninterruptible window until the
watchdog budget fires, with the gate failing open throughout.

### Two survey findings that would have sent the work to the wrong code

`connectors/fanotify.ParseEvent` is **not** in the privileged binary — `go list -deps
./cmd/openshield-agent` returns eight openshield packages and that is not one of them. The agent carries
its own duplicated, unexported decoders in `execmon` and `openmon`. Anyone looking for "the agent's
fanotify parser" under `connectors/` fuzzes something that never runs privileged.

And the IPC asymmetry is already right: the agent is the *client* on both sockets, so it decodes only
the fixed-width `ReadResponse` — no peer-supplied length, nothing to allocate from. A strength to
confirm, not a gap to close.

### The prediction was zero defects. It was wrong.

Stated in the proposal before starting, and left there: all three decoders bound their declared length
against the buffer before slicing, and on reading they look correct. They are correct — **on the
architecture the tests run on.**

`int(someUint32FromTheWire)` is **-1** on a 32-bit platform. Then every "is this past the ceiling?"
check passes, and the slice panics:

| Site | On 32-bit | Found by |
| --- | --- | --- |
| `execmon.decodeMeta` | `buf[4294967295:]` panics | `FuzzDecodeMeta` under `GOARCH=386` |
| `openmon.decodeMeta` | same, in the `FAN_OPEN_PERM` loop | `FuzzDecodeMeta` under `GOARCH=386` |
| `openipc.ReadRequest` | short allocation, then `body[:pathLen]` panics | an EXISTING test under `GOARCH=386` |
| the inotify record walk | `buf[16:15]` panics | reading the arithmetic while extracting it |

**The real finding is not three bugs. It is that the suite had never run on a 32-bit architecture**,
while `GOARCH=386` and `GOARCH=arm` both compile the agent today. The `openipc` site was already covered
by a test called `TestADeclaredLengthBeyondTheBoundIsRefusedBeforeAllocating` — the exact property that
fails — and it passed on amd64 forever. So the durable fix is a CI step, not four patches.

The order of the conversion is what decides it, and neither site says which discipline it relies on.
`connectors/fanotify.ParseEvent` converts to `int` **before** comparing, so its negative value trips the
under-run check and it is *accidentally* safe. The privileged decoders compare the unsigned field first,
so `0xFFFFFFFF < 24` is false and the guard lets it through.

### Fuzzing alone would not have found all of it

The inotify site came from reading the arithmetic during the extraction. No amount of fuzzing on amd64
would ever have reported it, because on amd64 it is correct. That is worth keeping: the fuzzer found two,
`GOARCH=386` on an existing test found one, and reading found one.

### An assertion that could not fail

The new targets assert declared bounds. One of them was decoration: every seed declared a huge length
and supplied no body, so `io.ReadFull` errored before the assertion was reached, and raising the ceiling
sixteenfold did not fail the target. It needed a seed carrying an over-ceiling body — which the fuzzer
would not have built inside any budget worth running. **The mutation is what exposed that**, and the
first attempt at that mutation failed to compile, so the compile was checked explicitly before the
result was believed (the D359 lesson, applied rather than relearned).

### Honest bounds

None of these is reachable through a real kernel or a well-behaved peer, which write real lengths. They
are latent panics in privileged code on two shipped architectures, not live holes — and the decoders'
own comments promise they survive malformed input.

After the fixes: seven targets, ~380M executions, no crashers, so `testdata/fuzz/` is empty. That is a
result, not a missing deliverable. The CI fuzz step is a **smoke test** and is labelled as one; twenty
seconds explores almost none of the space. The durable value is that `go test` replays a target's seed
corpus on every ordinary run, so the first crasher anyone finds becomes a permanent check for free.

The three decoders of `fanotify_event_metadata` are deliberately **not** unified. Fuzzing both privileged
ones is how one learns whether they behave identically; merging them first would destroy the evidence.

### And the 32-bit run found something bigger than a decoder bug

Extending the `GOARCH=386` run to `internal/agent` failed with `parser worker unavailable: EOF`. The
worker was not crashing — it was **refusing to start**:

```
openshield-worker: refusing to parse without a sandbox: sandbox: loading seccomp filter:
failed to assemble policy: found unknown syscalls for arch i386: accept
```

**The sandboxed worker cannot run on linux/386 at all**, and `make cross-compile` builds it happily
while nothing says so. That is the silent-gap shape (D31) at platform scale: the endpoint's content
parser is non-functional on an architecture the build supports.

**The second half is worse than the first.** `internal/agent/sandbox` is a DENYLIST naming `socket`,
`connect`, `bind`, `accept` and friends — and on i386 socket operations go through **`socketcall`**,
which is not in the list. So even if the filter assembled, it would block nothing: the parser could
reach the network by the one entry point the denylist does not name. The failure to assemble is what is
currently protecting the boundary, by refusing to parse rather than parsing under a filter that would
not hold.

That is the right direction (fail toward refusing), and it is protecting us **by accident** — the policy
never reasoned about a second syscall ABI. The denylist's own comment already concedes the shape of this:
it says an allowlist is stronger and that the denylist was chosen to avoid breaking on Go runtime
upgrades. An architecture with a different socket ABI is the same class of fragility from a direction the
comment did not anticipate.

**NOT FIXED HERE, and deliberately.** Adding `socketcall` would make the filter assemble on i386, at
which point the worker would start — with a sandbox this session cannot properly test the enforcement of.
Shipping a sandbox that looks applied and is not is a worse outcome than a platform that refuses to run.
The decision is an owner-level one: either support 32-bit x86 (port the policy and prove enforcement on
that architecture) or state that only 64-bit is supported and stop cross-compiling as though it were.
Recorded on the roadmap as an open item rather than guessed at.

---

## Round 46 (D365): what the integration suite actually executes, measured

The owner's question: *"make sure every code path is covered and executed in integration tests, so we
know everything is wired, there's no gaps and works as it should."* It had never been answered with a
number. The suite's evidence of value was that it keeps finding real defects, which is not the same
claim.

Measured across the **real shipped binaries** — `go build -cover -coverpkg=./...`, the suite pointed at
them through the harness's existing `OPENSHIELD_INTEGRATION_BIN_DIR` seam with `GOCOVERDIR` set:

| | |
| --- | --- |
| statement coverage, whole module, one integration run | **51.2%** |
| packages measured | 82 |
| at 0% | 6 |
| under 25% | 10 |
| under 50% | 23 |
| packages reachable from no `cmd/` binary | 9, all explained |

Reproducible as `scripts/coverage-integration.sh` rather than as a number in a document.

### The finding that mattered was not the number

**No CI job runs the integration suite. None. It never has.**

The `ledger` job in `ci.yml` runs *package* tests against a real Postgres — valuable, and not this.
`test/integration/` is the only place the built commands run as real processes, which makes it the only
place the wiring in `cmd/` is exercised. Grep the workflows for `-tags integration`, `test/integration`,
`make integration` or `make all`: no matches. It was reachable only by running `make integration` on a
developer's machine — and the standing local discipline is to run *targeted* tests, precisely because the
full gate is slow.

So the thing that proves the product is wired ran in no automated gate, while a guard existed for
overclaiming in the README.

### And it had already let something through

`seedTimeline` in `test/integration/timeline_test.go` snapshotted its ledger baseline **after** writing
the file it was then waiting for:

```go
os.WriteFile(...)       // the engine records a row ~90ms later
before := count()       // ...which this may already include
Eventually(60s, func() bool { return count() > before })
```

On a machine fast enough, `before` already contains the row and the loop waits out its full 60 seconds
for a second row that is never coming. Two tests, failing deterministically here, in both the
instrumented and the ordinary run. Every sibling in the suite that uses this pattern —
`execaudit_test.go`, `clipboard_x11_test.go`, `smtp_test.go`, `durability_test.go`,
`cefsyslog_test.go` — snapshots before the trigger. `timeline_test.go` was the only one that did not.

**An earlier pass in this session called these two failures "probable instrumentation overhead" and that
was wrong.** They fail without instrumentation. The lesson is narrow and worth keeping: a plausible
explanation for a test failure is not a diagnosis, and "it's the measurement's fault" is the most
seductive of the plausible ones because it requires no further work.

Both are now green in 4.4s, down from 122s of timeouts. The suite is wired into CI as its own job, with
`podman --version` as an explicit first step — because the suite *skips* without podman, so the naive
version of that job would have reported green while running nothing.

### A zero that was a real gap: RFC 5424 ingest

`internal/connectors/rfc5424` measured **0.0%** across the whole run while `internal/connectors/cef`
measured well. The cause is exact: `Server.cefSink` tries CEF first and falls back to RFC 5424 only when
that parse fails — and **every** syslog scenario in the suite sends a CEF payload. `cefsyslog_test.go`,
`syslogstream_test.go`, `metrics_test.go`: all CEF. The fallback could not be reached by any
configuration the suite produces.

Listener, parser and persistence were all real and all wired. The end-to-end path simply had no test
that could take it — which reads identically to working, right up until an operator points a non-CEF
device at the port.

`TestAPlainRfc5424LineIsStoredWithItsStructuredData` closes it, and asserts on the **structured data**
rather than on a stored row: an SD element landing in the same `fields` JSONB as a CEF extension is the
whole reason this connector exists over the BSD-syslog one, and a row-count assertion would pass against
a parser that dropped every `[id key="value"]`. Mutation-verified in both directions — disabling the
fallback fails it (93s, at the store assertion), and mapping `Fields: nil` fails it at the JSONB query.

### The other five zeros are gated, and one is a limit of the measurement

| Package | Why 0% |
| --- | --- |
| `internal/agent/watchdog` | fanotify permission mode needs root; covered on the rooted VM |
| `internal/dnsredirect` | `CAP_NET_ADMIN` + nft; VM-gated |
| `internal/dnssink` | reached only by `network_vm_test.go`, which skips without root |
| `internal/clipboard/x11` | needs an X display |
| `internal/agent/worker` | **not gated — unmeasurable.** See below. |

`internal/agent/worker` at 0% alongside `cmd/openshield-worker` at 48.2% is contradictory, and the cause
is `privileged.Worker.Close`: it closes the worker's stdin and then immediately calls
`cmd.Process.Kill()`. **A SIGKILLed process flushes no coverage profile.** The 48.2% on the binary comes
from workers that happened to exit on stdin EOF before the kill landed — startup paths, not request
handling. So the parse path that is the entire reason the privilege split exists is invisible to this
measurement, and **51.2% understates the truth by an unknown amount**.

Deliberately not changed here. Closing stdin, waiting briefly, then killing would be better shutdown
hygiene *and* would make the measurement possible — but changing production shutdown semantics to
improve a metric is the tail wagging the dog, and it belongs in its own ticket with its own reasoning.
Recorded on the roadmap.

### The static half needed no run, and is a stronger statement

`go list -deps ./cmd/...` gives everything a shipped binary can reach. The complement is not "0%
covered" — it is **cannot execute in any deployment however configured**. Nine packages, every one
explained: three test-only CI guards (`doccheck`, `fitness`, `packaging` — the last has *no
implementation file at all*), three doc-only parent packages, two spikes kept as the record behind D19
and T-005, and one platform-gated (`internal/connectors/filewatch`, imported by the `!linux`-tagged
`cmd/openshield-engine/watcher_other.go`).

That is now `scripts/check-cmd-closure.sh`, in `make quick`, `make check` and CI — ~2s, so it can gate
where the coverage run cannot. It fails in both directions: an unexplained package outside the closure,
**and** a stale entry that has become wired. Without the second the list accumulates until nobody reads
it, and becomes the hiding place it was built to prevent. Mutation-verified both ways.

The allowlist requiring a *reason* per entry is the mechanism, not decoration. `internal/connectors/smtp`
— parser, capture listener with per-session ceilings, idle timeouts, a concurrency cap, an event
producer, full tests, imported by nothing while the README described live SMTP inspection — is what an
unexplained line in that list looks like before anyone notices.

### What this does not close

A package can be imported by a binary and still be unreachable at runtime because no setting turns it
on. The closure check raises the floor; it does not close the class. And statement coverage is not path
coverage — every line of a function can run without its error branch ever being taken, which is exactly
why the 51.2% is a work list and not a grade.

---

## Round 47 (D367): the offline queue's recovery half, and a broker that comes back wrong

The enterprise gap assessment named four distributed properties the single-host fleet topology cannot
prove. **Offline-queue drain after a real disconnection** was one, and checking it found that the drain
had no test at all — not a weak test, none.

`TestTelemetryIsSpooledDuringAnOutage` stops the broker and asserts the spool becomes non-empty. D40/D67
claims "spool signed telemetry when the control plane is unreachable and **re-send it on reconnect**, so
an outage causes a gap, not silent loss". **No scenario had ever brought a broker back**, so
`Queue.Drain`, `SignedPublisher.Flush` and the NATS reconnect they depend on ran in nothing.

The half that was asserted is the half that costs nothing if it is wrong. A spool that fills and never
empties is indistinguishable from a working one until an investigator asks about the outage window.

### The assertion had to be the spool, not the row count

The agent keeps producing after recovery, so "rows increased" is satisfied by an agent that discarded
every spooled record and resumed — which is the failure under test. `Queue.Drain` removes a record only
after its send succeeds and stops at the first failure keeping the rest, so **an empty spool is proof
every record in it was delivered**, and proof that does not encode the on-disk format.

### The first version of the test accused the product of the worst version of the bug

It read the row count at the instant the spool emptied:

```
outage: 2 record(s) held on the spool, 2 row(s) stored before it
the spool emptied but only 0 row(s) appeared for 2 held record(s)
```

That is the wording of `Drain` removing records it never delivered. It was a race in the test. An empty
spool means the **broker** accepted them; the row appears only once the control plane has consumed them
off JetStream and written them — two milestones, the second lagging. Probing it directly showed
recovery working (2 → 20 → 40 → … → 120 rows).

Worth keeping because of the direction of the error: the count cannot distinguish "not yet stored" from
"thrown away", and the wrong reading is the alarming one. A less careful pass ships a bug report against
working code.

### What it did find: an empty-state broker wedges the fleet, silently

Before the JetStream store was moved into a volume, the restored broker had empty state and the drain
failed forever with `nats: no response from stream`. That is not a harness artifact to paper over — it
is a real defect, reproduced:

| Broker comes back… | Result |
| --- | --- |
| with its JetStream store (a restart) | recovers fully — 2 → 120 rows |
| with a fresh store (`podman rm` + recreate) | **never recovers; the control plane logs nothing** |

`natsx.EnsureTelemetryStream` is called from exactly two places — `controlplane.Run` and
`SignedPublisher.UseJetStream` — both at **process startup only**. Nothing recreates a missing stream.
The agent's publishes fail forever (at least logged agent-side); the control plane's durable push
consumer was deleted with the stream and it says **nothing at all**, while every agent's spool grows
toward its 10,000 ceiling and starts dropping the oldest records. A silent fleet-wide telemetry outage
is a direct D31 violation, and D31 is the reason the rest of this product is trustworthy.

Ordinary ops produces it: remove and recreate the broker container, or let an orchestrator reschedule it
onto new storage.

**Not fixed here, and the reason is specific rather than a shrug.** Re-ensuring the stream from the agent
on reconnect is the tempting one-line fix, and it would make things *worse*: the stream would be
recreated, publishes would succeed, the control plane's consumer would still be dead, and still no row
would appear — a state harder to diagnose than the current one, that looks fixed. The fix needs a
control-plane reconnect handler that re-ensures **and re-subscribes**, which is a lifecycle change in the
ingest path. Filed as PLAT-10 with the reproduction and with the minimum bar recorded: even if
self-healing is deferred, the server must say something.

`Stack.RestoreBrokerEmpty` exists now so the defect is reproducible in one call rather than
rediscoverable.

### Still unproven, and named rather than implied

- **A true network partition of the endpoint** — interface removed, different IP on rejoin — as opposed
  to a broker outage. The podman primitives are verified: rootless `network disconnect`/`connect` works
  cleanly, a `CGO_ENABLED=0` agent runs in an alpine container with the binary bind-mounted, and
  `host.containers.internal` is reachable from a container on a custom network. The test is not written.
- **The reconnect budget.** The agent passes NO reconnect options, so the NATS client defaults apply:
  `MaxReconnects=60` × `ReconnectWait=2s`. An endpoint offline for more than roughly two minutes gives
  up permanently and its spool never drains — a laptop closed for lunch is the normal case, not an edge
  case. This scenario's outage is far shorter and so neither proves nor disproves it. Next to measure.
- Clock skew, and per-node limits under real contention.

---

## Round 48 (D368): every long-lived process gave up on the broker after two minutes

Round 47 ended by naming the reconnect budget as the next thing to measure rather than assuming it either
way. Measured: it is a real defect, in every long-lived process in the product.

nats.go defaults to `MaxReconnects=60` with `ReconnectWait=2s` — roughly **two minutes**, after which the
client closes permanently and the process keeps running while never publishing or receiving again.
**Nothing passed a single reconnect option.**

| Outage (same broker, same port, state intact) | Result |
| --- | --- |
| 4 seconds | recovers fully — 2 → 120 rows |
| 150 seconds | **never recovers** — still 2 rows thirty seconds after it is back |

### The agent case is the one that matters, because the feature defeats itself

The spool exists so an outage causes a gap rather than silent loss (D40/D67). After the budget expires the
agent keeps producing into a spool **it can never drain** — so the spool fills to `OPENSHIELD_QUEUE_MAX`
and begins dropping the OLDEST records. A bounded outage silently becomes unbounded evidence loss, by way
of the mechanism built to prevent exactly that.

For the control plane the same default meant the whole fleet's ingest stopping permanently with the server
still running and reporting nothing wrong. For the engine and gateway: enforcement continues, the record
of it stops.

Two minutes is not a long outage. A laptop closed over lunch, a switch reboot, a VPN drop, a broker upgrade.

### Where it hid

The engine and gateway had a `natsOptions(log)` helper that looks like it exists to hold precisely this:

```go
if cfg == nil {
    return nil            // ← the common path: no options at all
}
return []nats.Option{nats.Secure(cfg.ClientConfig())}
```

The resilience of the connection depended on whether mTLS happened to be configured. Nothing in the name
or shape of that function hints at it.

### The test could not fail, and only the mutation said so

First version: a 135-second outage, on the arithmetic that 60 × 2s = 120s. Reverting `MaxReconnects` to 60
left it **passing** — because the jitter the same change adds makes the real budget 120–180s, so 135s never
exhausted it. The scenario was quietly re-proving what Round 47's drain scenario already covered.

**The fix had widened the very budget the test was sized against.** That is worth keeping as a pattern:
any threshold derived from the code under test must be re-derived after changing that code, and a mutation
is the only thing that catches it. Window now 200s; mutant fails on the spool never draining (383s), fixed
version passes with 80 records recovered (209s).

### No ClosedHandler, deliberately

The obvious addition logs "closed permanently — this process will never publish again" at maximum severity.
nats.go invokes `ClosedHandler` on an explicit `Close()` too, so that line would appear on **every clean
shutdown** — a maximum-severity warning in the log of every correctly-stopped machine is the one an
operator learns to scroll past. And with `MaxReconnects(-1)` the condition cannot arise: a permanent close
is only ever deliberate. All cost, no signal.

### A CI guard of mine had the same hole it was built to close

The `integration-suite` job added in Round 46 ran `podman --version` as its first step, on the reasoning
that the suite `t.Skip`s without podman and would otherwise report green having run nothing.

A runner then shipped a podman whose OCI runtime could not start anything —
`Error: OCI runtime error: crun: unknown version specified`, reproducible on that runner and absent on
another in the same fleet. **`podman --version` succeeds there.** So the guard would have passed while
every scenario skipped: exactly the failure it was written to prevent, one layer down. It now runs
`podman run --rm alpine:3 true`.

The same runner surfaced it through `TestRestoreDrillRunsEndToEnd`, which reported `pg_dump: exit status
126` — reading as a defect in the ledger's backup story when nothing had run at all. That test now skips
when the container **cannot start**, matched on the runtime's own error text rather than an exit code
(podman also returns the container's status, so a tool that genuinely exits 126 would be
indistinguishable). Kept narrow on purpose: a tool that ran and then failed still fails the test, because
that is the drill actually being broken.

### What this does NOT fix

**PLAT-10 is untouched.** A broker returning with empty JetStream state still wedges the fleet — the client
now reconnects forever, and the stream it needs is still not there. Reconnecting forever is necessary and
not sufficient.

And infinite retry is a policy choice with a cost worth stating: "the agent is running" no longer implies
"the agent is connected". The new disconnect log line is what makes that visible, and the fleet-side
dead-man's-switch is what makes it actionable.

---

## Round 49 (D369): a partitioned endpoint took four minutes to notice, and only a container could show it

Round 48 fixed the reconnect budget and closed by naming a true endpoint partition — the agent's own
interface vanishing, rather than the broker stopping — as still unproven. Proving it found a second defect
that the first fix could not have helped with.

### The two outages are not interchangeable, and this is the proof

A stopped broker sends a RST; the client knows at once. An endpoint whose interface is **removed** is left
holding a TCP connection that is dead and looks open. Nothing arrives to invalidate it, so nats.go's
keepalive is the only thing that can notice — and its defaults are `PingInterval=2m` with
`MaxPingsOutstanding=2`: **up to four minutes**. Throughout that window `IsConnected()` stays true, so no
reconnect is attempted and every spool drain fails.

The agent's own log was the diagnosis, and it is an absence rather than an error:

```
fleet-agent: flush stopped after 0 (still unreachable?): nats: timeout   (repeated)
```

No disconnect line. No reconnect line. Still repeating after the network came back. The spool went from 4
records to 76 while the scenario waited.

**D368's infinite reconnect cannot help here — you cannot reconnect a connection you do not know is
broken.** Two fixes that both read as "make the client resilient", and the first is invisible without the
second. That is the argument for testing the partition specifically rather than trusting that an outage is
an outage.

`PingInterval(20s)` + `MaxPingsOutstanding(2)` puts detection at ~40s. The scenario went from failing after
208s to passing in 66s, and the log now reads what it should:

```
nats: broker connection lost (nats: stale connection) — retrying forever; telemetry is being spooled
nats: broker reconnected to nats://osint-partnats-…:4222 — draining anything spooled during the outage
```

Mutation: the 2-minute default back → fails with 76 records still held. The constant is load-bearing.

### What the container topology cost, and what it bought

Two obstacles, both informative about the harness:

- **The stack's broker cannot join a bridge network.** The harness starts NATS in the default rootless mode
  and `podman network connect` refuses it: `"slirp4netns" is not supported: invalid network mode`. The
  scenario brings up its own broker on the bridge, published to a host port so the control plane still
  reaches it at 127.0.0.1 while the agent reaches it **by name** — which puts DNS inside the partition
  rather than beside it.
- **The agent must not enrol from inside the container.** The enrolment endpoint binds 127.0.0.1, and
  binding 0.0.0.0 would widen a listener on the developer's machine for a test run. So the agent enrols as a
  host process, persists its identity (D318), and the container starts with that identity and NO TOKEN — the
  stronger start anyway, since an agent needing a token to come back has been re-provisioned, not restarted.

Bought: the rejoin gets a **different IP** for free (10.89.1.3 → 10.89.1.4 in the run that proved it), so
"anything that assumed its own address survives the outage" is covered without arranging it.

### A misleading log line, caught in a PASSING test

`DisconnectErrHandler` fires on a deliberate `Close()` too, with a nil error. So every clean shutdown
printed:

```
broker connection lost (<nil>) — retrying forever; telemetry is being spooled, not sent
```

False on all three counts — nothing lost, nothing retried, nothing spooled. It was visible only in the
captured shutdown output of a test that **passed**, which is why it nearly survived. A misleading line on a
green run is the kind that later gets quoted in an incident review. `err == nil` is the discriminator.

Second time in this area the right answer was *do not log that*: the omitted `ClosedHandler` (Round 48)
fires on clean shutdown for the same reason. Worth stating as a pattern — **nats.go's connection handlers do
not distinguish "it broke" from "we closed it", so any of them used for alarming needs that guard.**

### The CI runtime, and a guard of mine that was right to go red

Round 48 replaced the `integration-suite` job's `podman --version` with a functional
`podman run --rm alpine:3 true`, because a runner shipped a podman whose crun could not start anything.
The next run went **red on that step** — which is the guard working: the suite genuinely could not run, and
reporting green would have been a lie.

Red for a reason we do not own is still not actionable, so the job now writes a `containers.conf` pinning
podman to **runc**, which these runners have and which works. The probe stays: if runc is missing too, the
job fails loudly rather than skipping quietly.

### Still unproven

**Clock skew** and **per-node resource limits under contention** — the remaining two of the four properties
the enterprise gap assessment named. Partition and offline-queue drain are now closed.

And this partitions ONE endpoint. A whole segment partitioning and reconnecting together is not exercised;
the reconnect jitter added in Round 48 is the mitigation for that and remains untested at scale.

---

## Round 50 (D370): PLAT-10 — the stream was created once, at startup, and never again

D367 reproduced this and deliberately left it. The reasoning then still holds and is why it took its own
change: the tempting one-line fix — re-ensure the stream from the agent on reconnect — would have recreated
the stream while the control plane's consumer stayed dead, so publishes would succeed and still no row would
appear. Fixed-looking and harder to diagnose than the original.

`natsx.EnsureTelemetryStream` was called from exactly two places, `controlplane.Run` and the producers'
`UseJetStream`, **both at process start**. A broker that came back without the stream stayed without it:
every publish refused with `no response from stream`, the durable consumer deleted along with the stream,
**the control plane silent**, and every agent's spool growing to its ceiling and dropping the OLDEST records.

### The obvious hook would have shipped a fix with a hole in it

`nats.ReconnectHandler` is where this belongs on first reading. But the failure is *"the stream is not
there"*, and that has causes with no disconnect attached: an operator running `nats stream rm`, a retention
change, a cluster losing the asset without dropping TCP. The connection stays healthy, no handler fires, and
ingest is down silently — the original bug with extra steps.

A `ConsumerInfo` on a 15s timer observes the **state** rather than an event about the state, so it catches
the causes nobody enumerated. That is the whole design decision.

### The repair is narrow, and that is also deliberate

Only `ErrConsumerNotFound` / `ErrStreamNotFound` trigger a rebuild. "If the check errored, rebuild" would
tear down and recreate a *working* durable consumer on every transient timeout — churning the thing
currently delivering telemetry, on the schedule of the network's worst moments. A false negative costs one
poll interval; a false positive costs a working subscription.

It also **announces before repairing**, so the log shows ingest went down even when the repair then fails.
A message emitted only on success documents the recoveries and hides the outages. Repairs and repair
failures are counted separately.

### What is NOT claimed

Records published while the stream was absent are gone — **refused** by the broker, not buffered by it. They
return only as producers drain their offline spools (D40/D67). This heals the channel, not its contents, and
the restore log says exactly that rather than implying a clean recovery.

The stream config is a constant, so a repair recreates it with the ORIGINAL settings — an operator's
deliberate tuning would be overwritten. Recorded rather than guarded, because the alternative is refusing to
heal, which is where this started.

### A check of mine lied, and it was the anti-lying check

The mutation (healing disabled) failed the scenario correctly — 198s against a 37s pass. But the guard I ran
first to make sure the mutant was real reported `MUTANT_COMPILES=no`, and it was wrong: an early `return`
makes the rest of a function unreachable, which **`go vet` rejects and the compiler accepts**. `go build`
confirms it built, and a 198-second timeout could only have come from a working binary.

Worth recording because D359's whole lesson is that the check itself must not be able to lie — and here the
check guarding against a false mutation result was measuring the wrong thing. `go vet` is not `go build`.

### The four properties, closed out

The enterprise gap assessment named four that a single-host fleet topology cannot prove. Two are now covered
by real tests — **network partition and rejoin** (Round 49) and **offline-queue drain** (Round 47, and this
round for the empty-broker variant). **Clock skew** and **per-node limits under real contention** remain
unproven and are still the honest answer to "what does the fleet simulation not tell you".

---

## Round 51: the coverage measurement re-run, after a day of changes

`scripts/coverage-integration.sh` (D365) exists so this number can be re-derived rather than quoted. The
first measurement predated D365–D380, so it was re-run.

| | Round 46 (D365) | Now |
| --- | --- | --- |
| statement coverage, real binaries | 51.2% | **52.7%** |
| packages measured | 82 | 83 |
| at 0% | 6 | **5** |
| under 25% | 10 | 9 |
| unreachable from any `cmd/` binary | 9 | 9 |
| integration suite | **2 failures** | **0 failures** (888s) |

### The two results worth reading

**`internal/connectors/rfc5424`: 0.0% → 73.6%.** That was Round 46's real finding — a wired, tested,
reachable ingest path that no configuration the suite produced could exercise, because every syslog scenario
sent CEF. It is now the second-best-covered connector in the tree. The measurement found the gap and the
same measurement confirms it closed, which is the whole argument for the number being reproducible.

**The suite is green under instrumentation.** Round 46 ran with two failures (`seedTimeline` snapshotting
its ledger baseline after the write it was waiting for) and this one has none, including the 200-second
reconnect-budget scenario and the container partition. So the earlier failures were the defect they looked
like, not instrumentation overhead — which is what I wrongly assumed the first time.

`internal/connectors/objectstore`, added today, measures 79.1%.

### The five remaining zeros, unchanged in kind

| Package | Why |
| --- | --- |
| `internal/agent/watchdog` | fanotify permission mode needs root; covered on the rooted VM |
| `internal/dnsredirect` | `CAP_NET_ADMIN` + nft; VM-gated |
| `internal/dnssink` | reached only by `network_vm_test.go`, which skips without root |
| `internal/clipboard/x11` | needs an X display |
| `internal/agent/worker` | **not gated — unmeasurable.** `privileged.Worker.Close` SIGKILLs, and a killed process flushes no profile. Still open, still roadmapped. |

The last one is why 52.7% understates the truth by an unknown amount, over the parse path the privilege
split exists for. A number with a known blind spot is more useful than one without, provided the blind spot
is stated every time the number is.

### What did not move, and that is the finding

The unreachable set is still 9, and still the same 9 — three test-only guards, three doc-only packages, two
spikes, one `!linux`-gated. Everything added across D365–D380 (objectstore, the SCIM and operator-role
surfaces, clock skew, ingest healing, transport resilience) is inside the `./cmd/...` closure. The guard
that would have caught a new unwired feature had nothing to report, which is the outcome it is for.

---

## Round 52 (D381–D383): "it's gated" was doing too much work

The 52.7% report said the remaining zeros were environment-gated and left it there. Pressed on whether
that was really the end of it, every one of the excuses turned out softer than it looked — and three of
them were hiding defects rather than merely hiding code.

### The excuses, and what each was covering for

| Claim | What was actually true |
| --- | --- |
| "root-gated, runs on the VM" | **Ran nowhere.** 12 tests — inline `DENY_EXEC`, the open gate's EPERM, both fail-open paths, application whitelisting, mount-scope refusal — executed only when somebody remembered. Now a CI job, verified on the VM first. |
| "unmeasurable" | **We SIGKILLed the parser.** `exec.CommandContext` kills on cancellation, pre-empting `Worker.Close` entirely. 0% → 75.6%. |
| "root-gated" (dnsredirect) | Ran nowhere **and was broken** — conntrack, below. |
| "needs a display" (clipboard/x11) | **Does not skip. Hangs**, for the full 10-minute test timeout, and reports 0% — which reads exactly like a skip. |

GitHub runners are full VMs with passwordless sudo. The privileged gating was never about CI being unable;
it was about nobody having wired it.

### The conntrack one is the one worth remembering

`internal/dnsredirect` passed test-by-test, passed the FIRST package run under real root, and failed the
next — a different test each time, always `connection refused`.

A nat REDIRECT decision is cached **per flow**, and removing the rule does not flush the entries it made; a
UDP conntrack entry outlives the test by ~30s. A later query whose ephemeral source port collided with an
earlier one was still DNAT'd to a resolver port that had since closed. **The damage was done by the previous
run**, which is why nothing in the current one explained it and why a single test always passed.

First fix — clearing both rule chains — was necessary, correct, and did not help: the leftover was never a
rule. Fixed by giving each test its own loopback upstream, so no stale tuple can match. Four consecutive
clean runs where it previously failed two in three.

### And the measurement itself was the wrong measurement

| | Integration only | Unit + integration |
| --- | --- | --- |
| total | 55.2% | **70.2%** |
| packages at 0% | 4 | **0** |
| under 50% | — | 7 |
| 85%+ | — | 43 of 86 |

`internal/dnssink` reads 0% on the integration run and 72.5% on its own tests. A number that calls that
package untested is not measuring what its reader thinks.

### What is still understated, and it is structural

The merged figure covers unit + integration. It does NOT include the privileged runs, because those happen
under `sudo` in a separate job that emits no coverage. So `internal/agent/openmon` (11.2%),
`cmd/openshield-agent` (18.6%), `internal/agent/execmon` (30.7%), `internal/dnsredirect` (39.3%) and
`internal/clipboard/x11` (20.2%) are all reported below what is actually exercised — their tests run, just
not in a run that is measured.

**Now done.** The privileged binaries were rebuilt with `-cover`, run as root on the VM with
`-test.gocoverdir`, and merged as a third dataset (`scripts/coverage-all.sh`). The overall number barely
moves — 70.2% → **71.1%** — and the per-package move is the whole point:

| Package | unit+integration | + privileged |
| --- | --- | --- |
| `internal/agent/openmon` | 11.2% | **85.0%** |
| `internal/agent/execmon` | 30.7% | **80.4%** |
| `internal/dnsredirect` | 39.3% | **77.8%** |
| `internal/agent/watchdog` | 66.7% | **90.9%** |
| `internal/clipboard/x11` | 20.2% | **66.7%** |
| `cmd/openshield-agent` | 18.6% | **51.7%** |

Those are the fanotify permission gate, the exec gate and the watchdog — the components whose failure wedges
a machine. Reporting them in the teens because the measurement could not reach them is worse than not
measuring: it invites exactly the "well, it's gated" shrug that let twelve of those tests run in no
automated gate for months. `coverage-all.sh` therefore prints a LOUD warning when the privileged set is
absent, naming which packages are being understated and by how much.

### The work list, with every excuse now spent

> **The table below is WRONG and is kept as written. See Round 53.** The 71.1% headline and the
> `internal/controlplane` row are artefacts of a measurement taken with the database down. Corrected figures
> are 77.2% overall and 76.9% for `controlplane`. The row that survived is `printguard`.

Three packages under 50%, and one of them does not count:

| Package | | |
| --- | --- | --- |
| `test/integration` | 14.8% | the harness measuring itself — not meaningful |
| `internal/printguard` | 46.4% | real |
| `internal/controlplane` | 49.6% | real, and the largest package in the tree — an operator's whole surface |

46 of 87 packages sit above 85%. So the answer to "is there more that can be tested" was yes, and it was
mostly not more TESTS — it was measuring the ones that already existed, and finding that four of them
hung, were broken, or ran nowhere while looking green.

## Round 53 (D386): the measurement made the same mistake it was built to find

The work list above named `internal/controlplane` — the largest package in the tree — as one of two with no
excuse, at 49.6%. That was not true. It is 76.9%.

The tell was in the sweep's own log, and I had read past it:

```
ok  github.com/lucianoengel/openshield/internal/controlplane  0.933s  coverage: 6.0% of statements in ./...
```

Nought-point-nine seconds. That package takes **a hundred seconds** when it can reach a database. I had
removed the `osdev-pg` container before starting the sweep, so every Postgres-backed test skipped, and the
merged report attributed the resulting hole to the tests rather than to the run. `internal/controlplane/scim.go`
read as **nineteen functions at 0%** — code written, tested and mutation-verified the same day.

This is precisely the error class the whole exercise had spent a day finding elsewhere: *a dependency absent,
the result read as "untested"*. It is what made twelve root-gated tests look like they had no coverage, and
what made `internal/dnsredirect` look like dead weight. Committing it inside the tool built to prevent it is
worth recording rather than quietly fixing, because the failure is not carelessness about Postgres — it is
that **a measurement which cannot reach its dependencies reports a smaller number instead of an error**.

`scripts/coverage-all.sh` now probes `127.0.0.1:55432` and refuses to run without it, and passes
`OPENSHIELD_REQUIRE_POSTGRES=1` so a missing database is a test FAILURE rather than a skip. The same script
already refused to report a zero-profile integration run and a parse yielding no rows; this is the third
instance of one rule — *when the measurement is degraded, say so instead of publishing the degraded number*.

**Corrected, all three datasets merged (unit with a database + integration + privileged):**

| | before | corrected |
| --- | --- | --- |
| overall | 71.1% | **77.2%** |
| `internal/controlplane` | 49.6% | **76.9%** |

| under 50% | 50–70% | 70–85% | 85%+ |
| --- | --- | --- | --- |
| 2 | 12 | 26 | 47 |

### What survived: a wire protocol with no tests at all

`internal/printguard` was the one row on the old work list that was real, and the reason is starker than a
percentage. It had **no test files**. Its 46.4% was entirely incidental — integration tests driving it from
the outside, never once exercising a malformed frame.

It is the CUPS filter's IPC: 332 lines that decode a frame wrapping *a document from anywhere*, running in
the spooler's chain where a crash is a failed print job. Its own package comment invokes `execipc`'s
discipline — "lengths validated BEFORE allocation" — and `execipc` has a fuzzer. This had nothing.

Now 88.4%, and the tests were checked against six mutants rather than trusted:

| mutation | killed by |
| --- | --- |
| `ReadResponse` accepts an unknown verdict byte | `TestResponseRoundTripAndRejection` |
| the job-length bound is removed | `TestDeclaredLengthIsCheckedBeforeAllocating` |
| the metadata-field bound is removed | same |
| a failed evaluation is answered as ALLOW | `TestAnEvaluationFailureIsAnErrorNotAnAllow` |
| the response-id cross-talk guard is removed | `TestAMismatchedResponseIDIsRefused` |
| the stale socket is not unlinked on restart | `TestAStaleSocketDoesNotWedgeARestart` |

Two of those are load-bearing in a way worth naming. **An unknown verdict byte must be an error**: read
permissively as "not deny, therefore allow", any corruption or version skew of that single byte silently
disables print control while still looking like a decision. And **a failed evaluation must be dropped, not
answered**: the filter does end up allowing the job — that is the documented fail-open — but it must arrive
there through an *error*, so the failure is visible rather than laundered into a verdict that reads exactly
like a considered allow.

The job-length test declares two sizes deliberately. `0xFFFFFFFF` shows what the bound is really preventing
— a peer-supplied length is an allocation primitive. `MaxJobBytes+1` is what makes the bound's *removal*
detectable, because a decoder without it allocates 8 MiB, hits EOF, and reports a truncated frame instead of
an oversize one. A test that only used the absurd value would have made the mutant allocate 4 GiB to prove
the point.

Both decoders also gained fuzzers, wired into CI's existing fuzz step at the same 100,000-execution budget as
`openipc`. The request fuzzer asserts more than "does not panic": anything that decodes must respect the
bounds the decoder claims to enforce, and must re-encode — a value that cannot be written back is one the
decoder invented.

## Round 54 (D387): the credential-minting tool, and a row on the work list that was never work

Next on the corrected list was `internal/core/corev1` at 57.2%. It is **eleven `.pb.go` files and nothing
else**. That number measures how much of protoc's marshalling boilerplate some test happened to walk
through; raising it would mean writing tests for generated code to move a figure. It was sitting on a
published work list directly beneath two packages that genuinely needed tests, reading exactly like them.

So `coverage-all.sh` now classifies a package as generated when it contains `.pb.go` files and no
hand-written `.go` at all, and prints those rows **separately, below the work list, still with their
numbers**. Deleting them would be its own dishonesty — a filter nobody can see is indistinguishable from a
filter that is wrong, and the next person diffing this against `go tool covdata percent` would find rows
missing with no explanation. Exactly one package in the tree matches.

### `cmd/openshield-provision`: 12.6% → 57.1%

This is the tool that mints every credential the system trusts — the fleet CA, role-tagged agent and
operator certificates, zero-trust client certificates, escrow, witness and risk keypairs, the TLS
interception CA, and the per-agent posture roster. 974 lines. It had one test file, 150 lines, covering
`recover.go` and nothing else.

The invariant worth the most here is the least interesting to look at: **which files are private**. Whether
`ca-key.pem` lands at 0600 or 0644 is carried by nothing but the mode argument at one call site. Written
world-readable, every certificate it minted stays valid, every other test still passes, and the only symptom
is that any local account can mint an agent or operator identity. Six such call sites are now asserted — and
asserted on the *group/other bits* rather than an exact `0600`, because `os.WriteFile` applies the umask and
an exact comparison would be testing whoever ran it.

Nine mutants, eight killed:

| mutation | killed by |
| --- | --- |
| the CA key is written world-readable | `TestPrivateArtifactsAreNotReadableByAnyoneElse` |
| the escrow private key is world-readable | same |
| an issued leaf's key is world-readable | `TestAnIssuedCertificateChainsToTheCAAndCarriesItsRole` |
| the posture signing key is world-readable | `TestEnrollingAnAgentWritesARosterLineAndAPrivateKey` |
| re-enrolment appends a second line for one agent | `TestReEnrollingAnAgentReplacesItsLineRatherThanAddingASecond` |
| a malformed roster line is silently dropped | `TestAMalformedRosterIsRefusedAndLeftUntouched` |
| the roster is truncated instead of appended | `TestEnrollingASecondAgentKeepsTheFirst` |
| operator comments are dropped from the roster | `TestRosterCommentsSurviveEnrolment` |
| the client-certificate `--group` check is removed | **survived** |

**The survivor is reported rather than papered over, because what it revealed is worth more than a ninth
kill.** The check exists *twice* — once in this command and again in `provision.IssueClientCert`. Removing
either one alone leaves the property intact and the test green, which is what defence in depth is supposed
to look like. The risk is that a test written against one guard silently passes on the other's behalf, so
the property was re-checked with **both** removed: that does fail the test. The test comment now says so.
A surviving mutant is only a problem when you cannot explain it.

The roster tests are the other half. `posture.go` carries twenty-two lines of comment on why enrolment
appends rather than rewrites — *"a command that truncated the roster would silently un-enrol every other
agent"*, surfacing as "the fleet lost its posture signal after we added a laptop" — and until now nothing
exercised it. Four of the eight kills land there, including the one that matters most operationally: a
malformed roster is refused **and the file is left byte-for-byte untouched**, so a tool that cannot safely
rewrite the file does not rewrite it at all.

## Round 55 (D389): the same hole, one package over — the transparent inline plane

Chasing percentages on `cmd/*` wiring would have missed this. The better question was *which functions are
still at 0%*, which is how `scim.go` surfaced, and it put `internal/gateway` at the top with thirteen —
**eight of them the TPROXY lifecycle**: `RunTProxyWithRules`, `InstallTProxyRules`, `RemoveTProxyRules`,
`SuperviseTProxy`, `ListenTransparent`, `Serve`, `runAll`, `bestEffort`.

The package ships **four `*_kernel_test.go` files** covering exactly that code: TPROXY redirect, SNI
blocking, the self-installed nft rules, and the supervisor re-arming after a listener death. All are gated
on root for `CAP_NET_ADMIN`. None of them ran in any automated gate — the kernel job compiled `openmon`,
`dnsredirect` and the integration suite, and stopped there.

This is inline **prevention**: the plane that drops a flow rather than reporting it.

The finding is the same shape as Round 52's, and it survived for the same reason: *"internal/gateway has
kernel tests"* and *"CI runs internal/gateway's kernel tests"* look identical from outside. The only way to
tell them apart is to read the job.

Unlike `dnsredirect` — which turned out to be broken the first time it was actually executed — these were
fine. All five passed on the first run under real root on the VM. They were simply never run.

Both halves were verified before wiring, because the two most recent CI failures came from skipping exactly
these steps: D385 shipped a job whose `go build -o DIR` had never been executed as written, and D388 shipped
a guard that fired on a legitimate result. So: the tests were run under root (5 PASS, no skips), and then
**the step body itself** was run verbatim on the VM (`5`, exit 0). Verifying the tests and verifying the job
are different acts.
