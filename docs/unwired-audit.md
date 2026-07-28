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
