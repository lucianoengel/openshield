# Invariants

The load-bearing security properties of OpenShield, each with **the test that fails when it regresses**.

This document exists because of what building the product taught: a stated property is worth nothing
until something enforces it, and an enforcement is worth nothing until something proves the enforcement
is reachable. Over one audit round (D287–D297) this codebase was found to contain a kill switch no binary
installed, a four-eyes gate that could not be satisfied, a config store nothing could write, an encrypted
file nothing could decrypt, and a signed-feed loader that sat unused while the gateway read its threat
feed unverified. **Every one of those had passing unit tests.**

So each invariant below names its test, and each test has been **mutation-verified**: the enforcement was
deliberately removed and the test observed to fail. A row here is a claim backed by a demonstration, not
by a comment.

`internal/doccheck` enforces that every test named here still exists — a renamed or deleted test breaks
the build rather than silently turning a row into prose.

---

## INV-1 · A compromised control plane cannot cause arbitrary endpoint code execution

**Why it is the first invariant.** The control plane is the most attractive target in the system: it
reaches every endpoint. If compromising it yielded arbitrary execution on the fleet, nothing else here
would matter.

**What holds it.** Two closed vocabularies, enforced at the boundary where a name becomes a behaviour:

- The **action set** (D14). A policy's decision is a NAME mapped through a fixed table; a name outside it
  is refused, never defaulted. There is no action meaning "run this".
- The **intent verbs** (ADR-12) and the **fleet-control verbs** (PLAT-9). A signed message from the
  control plane can say `CONTAIN`, `ELEVATE_SCRUTINY`, `REVOKE_TRUST`, `ENFORCEMENT_DISABLE` or
  `ENFORCEMENT_RESTORE` — and nothing else is expressible on the wire.
- The **playbook step registry** (SOAR-4). Orchestration configuration selects from implemented steps; it
  cannot name an operation.

The consumer decides what a verb means locally. The control plane publishes DATA; it never commands.

**Tests:** `TestUnknownActionFails`, `TestActionMappingIsComplete` (`internal/policy`).

**Mutation:** removing the `actionFromName` refusal so an unmapped name falls through → `TestUnknownActionFails` FAILS.

**Honest limit.** This bounds what a compromised control plane can *express*. It does not bound what a
compromised control plane can do with the verbs it legitimately holds: an attacker who owns it can
`CONTAIN` every subject, and four-eyes (SOAR-3) is what makes that require a second human rather than
what makes it impossible.

---

## INV-2 · No policy evaluation, and no parsing of attacker-controlled bytes, happens in privileged code

**Why.** The privileged agent holds `CAP_SYS_ADMIN` and answers fanotify permission events. A parser
memory bug in that process is host compromise — the failure mode behind repeated RCEs in comparable
products (ClamAV CVE-2025-20260, a PDF-parser heap overflow in a privileged daemon).

**What holds it.** The two halves are separate **binaries**, so the ban is a property of the dependency
graph rather than of which code path runs. `scripts/check-agent-deps.sh` walks the privileged binary's
transitive imports and fails the build on any parser or decoder — `archive/*`, `compress/*`, `encoding/*`,
the template packages, and protobuf including the generated `corev1`. The exec-verdict transport is
hand-rolled precisely so that last line can stay true (HIPS-3 increment 2a).

**Tests:** `scripts/check-agent-deps.sh` and `scripts/check-core-deps.sh`, both run by `make all`.

**Mutation:** adding `_ "encoding/json"` to `cmd/openshield-agent` → the check FAILS, naming the import.

**Honest limit.** This proves the privileged binary cannot *link* a parser. It does not prove the kernel
interface it does use is memory-safe, and it says nothing about the unprivileged worker, which parses
hostile input by design — that risk is carried by seccomp, no network, and cgroup limits instead.

---

## INV-3 · Evidence cannot be rewritten below an anchor

**Why.** The audit ledger is the artifact every other claim rests on. If an attacker who reaches the
database can rewrite history, detection and response are theatre.

**What holds it.** A forward-secure hash chain: each entry commits to the previous entry's hash under a
key that EVOLVES, so an attacker who compromises the agent cannot forge entries from *before* the
compromise. Truncation and reordering break the chain. External anchoring (D64) closes the remaining
gap — a witness in a trust domain the deployer does not control signs the head, so history below an
anchor cannot be silently shortened.

**Tests:** `TestDeletedEntryIsDetected`, `TestReorderedEntriesAreDetected` (`internal/core`);
`TestLedgerIsAppendOnly`, `TestDeletedRowIsDetected`, `TestTombstonedLinkStillChecked`,
`TestAnchoringCompletenessBoundary` (`internal/store/postgres`);
`TestTheAnchorBinaryMovesCompletenessToAnchored` (`test/integration`) proves the anchor tool actually runs
— it was implemented with zero callers for an entire phase, and a chain nobody witnesses verifies as
permanently `unverified`.

**Mutation:** removing the previous-hash comparison in `internal/core/ledger.go` → four tests FAIL across
two packages.

**Honest limit, and it is the important one.** Anchoring's guarantee is only as good as the witness's
independence: a witness key the deployer holds attests to very little. The undetectable-loss window is
the interval between anchors, and the schedule chooses that window. Host root still defeats at-rest
protection on the endpoint (D16) — this is tamper-EVIDENCE with forward integrity between anchors, never
tamper-proofing.

---

## INV-4 · Unverified telemetry is never evidence

**Why.** Every downstream claim — correlation, incidents, response — rests on telemetry being
attributable. If a forger on the broker can manufacture evidence, an attacker can manufacture an incident
against anyone, or bury their own.

**What holds it.** Enrolled agents sign their telemetry; the control plane verifies before marking a row
`verified`, and every analytical path filters on it (D44). Unsigned telemetry may be *stored* — the
legacy self-asserted path — but never counted.

**Tests:** `TestUnsignedTelemetryIsNeverStoredAsEvidence`, `TestEnrolledAgentTelemetryIsStoredVerified`,
`TestARevokedAgentStopsBeingTrusted` (`test/integration`).

**Why these are integration tests.** The first version of the rejection test was VACUOUS: it started an
unenrolled agent and asserted no verified rows appeared, which passed because that agent publishes
nothing at all. An attacker does not use our binary. The test now publishes forged telemetry directly
onto the broker and asserts arrival FIRST — a negative test must prove the negated thing was attempted.

---

## INV-5 · Enforcement can be stopped without stopping detection

**Why.** "How do I stop this?" is the question a CISO asks before "what does it detect?". If the only
answer is *stop the process*, then stopping enforcement also destroys the detection and the audit trail —
exactly during the incident the product itself is causing.

**What holds it.** A kill switch that sits between the DECISION and the ENFORCER. Classification, policy
and the ledger all still run; only the enforcement call is skipped. It is reachable two ways — a local
break-glass file for when the control plane is unreachable, and a signed, four-eyes-gated, replay-bounded
and expiring fleet control — and it fails toward ENFORCING: absence is never engagement.

**Tests:** `TestAFleetWideDisableReachesAGatewayAndStopsEnforcement`,
`TestTheLocalBreakGlassFileStopsEnforcement` (`test/integration`).

**Mutation:** each install site removed, the watcher removed, and absence-means-engaged — all five FAIL.

**This invariant was FALSE until D287.** Every mechanism above existed and was tested; no shipped binary
installed any of it. It is listed here with that history because an invariant's value is in being
enforced, and this one spent a long time being merely written down.
