# Threat Model

**Read this before believing anything OpenShield appears to promise.**

This document exists because the project's original brief implied guarantees it cannot deliver.
Three adversarial review rounds established what a host-based agent can and cannot actually do.
Everything here constrains the product on any machine — none of it is an artefact of the
development environment.

## Who this stops

| Adversary | Local admin? | Stoppable by a host agent? |
|---|---|---|
| **Careless insider**, no intent | No | **Yes.** This is the design centre — accidental copies to USB, uploads, pastes. |
| Malicious insider, **no** local admin | No | **Partially.** Cannot disable the agent, but can route around unhooked paths (rename/unlink, screenshots, phone camera). |
| Malicious insider **with root on their own machine** | Yes | **No.** |
| External attacker who has compromised the host | Effectively yes | **No.** |

## Why root defeats it

Anyone with root can `systemctl stop` or `mask` the unit, boot a live USB and mount the disk
elsewhere, run the exfiltration inside a VM the agent cannot see, unload the kernel hooks,
`LD_PRELOAD` the binary, or simply block egress so no decision ever syncs. None of these have a
technical fix that doesn't require distrusting the operating system the agent depends on —
which would mean hypervisor-level or hardware-attested controls, out of scope for this project.

**The honest goal is tamper-*detection*, not prevention** (D16): heartbeat / dead-man's-switch,
"agent last seen" per host, and an audit event the moment the unit stops.

Practically, most engineering laptops are the root case. On self-administered machines this is
telemetry, not a fence.

## What evasion looks like

Against a *motivated* adversary, content classification is close to useless: encrypt or
password-protect before copying, compress, base64, split across files, retype, screenshot, or
print. Every one of these defeats pattern matching completely — and patterns are what runs on
the endpoint (D5), because NER is not endpoint-viable.

Against a *careless* user copying a spreadsheet to a personal USB stick, it genuinely works.

**True-positive rate against a motivated adversary is near zero. That is not a bug to fix
later; it is the shape of the problem.**

## Fail-open is a sanctioned bypass

Blocking enforcement must fail open or a stalled agent hangs the machine (D3). But that means
an attacker who makes classification slow — a huge file, a zip bomb, a pathological regex, or
just load — converts every Block into an Allow. Mitigated, not eliminated (D17): fail-open is
per-policy, every timeout-allow is loudly audited, scan budgets are capped, and timeout *rate*
is itself a monitored signal.

## The agent is an attack surface

A root process holding `CAP_SYS_ADMIN` that parses attacker-controlled documents is how
security tools make organisations less secure. ClamAV shipped **CVE-2025-20260**, a PDF-parser
heap overflow enabling RCE; Defender and Sophos have comparable histories. Hence D13: parsing
runs in a separate unprivileged, sandboxed, network-less worker, and the privileged process
never decodes attacker-controlled bytes.

## What the README may and may not claim

**May claim:** local-first visibility into data movement on Linux endpoints · friction and
audit for careless insiders · a tamper-*evident* trail with forward integrity between anchors ·
observe-only by design in Phase 1, so it cannot hang or brick a machine.

**May not claim:** prevention of data exfiltration · "stops insider threats" · tamper-*proof* ·
any guarantee that classification catches deliberate leaks · parity with commercial DSPs on
efficacy against motivated actors.

The first researcher who runs `systemctl stop` will publicly disprove anything stronger.

## Consequence for dogfooding

The owner has root on the fleet this is tested against, which is the bottom-half case above.
Dogfooding validates the pipeline, the classifier, the plumbing and the operability bar. It
**cannot** validate the product as a control. That is expected, and it is not a failure.

---

# Trust boundaries across the platform

Everything above is about the ENDPOINT adversary. This half is about the platform: what an attacker
gains by compromising each component, and the guard that bounds it.

**Each row names a guard and where it is proven.** Where a boundary is weaker than it sounds, that is
stated in the row rather than left for a reader to discover. Several entries carry a note about a period
when the guard existed and was UNREACHABLE — those are not history for its own sake: they are why the
"proven by" column is a test that runs the shipped binaries, not a code reference.

## Compromised control plane

**What it gets:** the fleet's aggregate telemetry, incident state, and the ability to send every message
the control plane can legitimately send.

**What bounds it:** the CLOSED VOCABULARIES (D14, ADR-12). A decision is a NAME mapped through a fixed
table; an intent is one of three verbs; a fleet control is one of two; a playbook step is one of seven.
There is no message meaning "run this". The endpoint decides locally what a verb means — the control
plane publishes DATA, it never commands.

**Proven by:** INV-1 in [INVARIANTS.md](../INVARIANTS.md), mutation-verified.

**Honest limit, and it is a real one:** this bounds what a compromised control plane can EXPRESS, not
what it can do with the verbs it legitimately holds. An attacker owning it can CONTAIN every subject in
the fleet. Four-eyes (SOAR-3) makes that require a second operator's approval; the blast-radius ceiling
caps how many subjects one publication may target. Neither makes it impossible — they make it noisy and
bounded.

## Compromised gateway

**What it gets:** plaintext of every proxied flow it terminates, and the ability to allow what should be
blocked.

**What bounds it:** almost nothing about the flows themselves — a gateway that proxies your traffic can
read your traffic, and no design here changes that. What IS bounded is EVIDENCE: the gateway holds a
forward-secure ledger signer, so it cannot rewrite entries from before its compromise, and the control
plane verifies telemetry signatures independently. A gateway that starts lying is a gateway whose lies
begin at a detectable point.

**What it does NOT get:** the ability to make endpoints do anything. It is not a publisher of intents or
fleet controls, and an endpoint verifies those against the control plane's key.

## Compromised endpoint agent

**What it gets:** everything on that host. See "Why root defeats it" above — this is the same case.

**What bounds it:** FORWARD SECRECY. The ledger's signing key evolves, so an attacker who takes the agent
cannot forge entries from BEFORE the compromise. External anchoring (D64) closes the truncation gap: a
witness signs the head, so history below an anchor cannot be silently shortened.

**Proven by:** INV-3, mutation-verified — removing the chain link fails four tests across two packages.

**Honest limit:** the undetectable-loss window is the interval between anchors, and the witness's
independence is the whole guarantee. A witness key the deployer holds attests to very little.

## Compromised administrator

**What it gets:** the console, and therefore configuration, cases, and the response surface.

**What bounds it:** FOUR-EYES on the acts that matter — closing an investigation, disabling enforcement
fleet-wide, containing a subject. The requester and the approver are taken from client CERTIFICATES,
never from a request field, so an administrator cannot approve their own action by naming someone else.
Every configuration change is a revision with an author, and a rollback is a NEW revision: the audit
trail cannot be rewound by the same authority that writes it.

**Proven by:** `TestFourEyesCaseClosureRefusesTheRequester`, `TestAHighImpactIntentNeedsTwoOperatorsAndThenReachesTheBroker`,
`TestRollbackRestoresValuesAsANewRevision`.

**Honest limit:** four-eyes is arithmetic on identities, so it is exactly as strong as the CA's issuance
discipline. Whoever can mint an operator certificate can be both pairs of eyes.

## Offline endpoint

**What it gets:** time. Policy is local, so an endpoint enforces while disconnected — but it also stops
reporting, and stops receiving revocations, intents and fleet controls.

**What bounds it:** the DEAD-MAN'S SWITCH. An agent that stops reporting becomes visible as overdue
rather than as quiet. Every intent and fleet control carries a mandatory TTL, so an endpoint that
reconnects after one lapsed does not apply a stale containment.

**Proven by:** `TestAnOverdueAgentIsReportedMissing`.

**Honest limit:** an attacker who takes a host and keeps it offline gets an unbounded window locally.
Detection is that the host went quiet, which is indistinguishable from a laptop in a drawer.

## Replay

**What it gets:** re-delivery of a legitimate message — a captured fleet DISABLE re-sent after an
operator restored enforcement is the sharpest case.

**What bounds it:** a MONOTONIC SEQUENCE, stored rather than held in memory so that neither a
control-plane restart nor a CONSUMER restart reopens the window, plus expiry evaluated ON READ by the
consumer. A control at or below the highest applied sequence is refused; an expired one is refused even
if the issuer is gone.

The consumer's half of that sentence was false until SEC-B, and it is worth recording why rather than
just correcting it. The publisher's sequence had been persisted since D66; the consumer's — which is
where a replay is actually refused — was a `uint64` struct field, so every restart reset the bound to
zero and every captured control replayed, bounded only by its own TTL. The claim and the code had drifted
apart in the direction that reads as safe. Both endpoints now persist the bound
(`OPENSHIELD_FLEET_CONTROL_SEQ_FILE`, defaulted rather than opt-in), write it BEFORE applying a control,
and refuse a control they cannot persist.

**Honest limit:** a deployment may set that path empty — a read-only root filesystem is a real
deployment, and refusing to start there would be worse than the window. The agent then says at startup
that its replay bound is in memory. If you accept it, the window is "everything captured since the last
sequence reset, until each control's expiry".

**Proven by:** `TestAFleetWideDisableReachesAGatewayAndStopsEnforcement` exercises the accepted path;
`TestARestartDoesNotReopenTheReplayWindow` and `TestTheBoundIsPersistedBeforeTheControlIsApplied` cover
the persistence; the remaining replay and expiry refusals are covered in `internal/intent`.

## Malicious insider with an operator role

**What it gets:** whatever their tier allows — and the read surface is the dangerous half, because
reading an investigation is how one learns what is known about them.

**What bounds it:** VIEW AUDITING (D20/L1). Who LOOKED is recorded, not only who acted, and the record is
written BEFORE the evidence is returned — a read that fails to record does not happen. Tiers separate
reading from acting, and acting from administering.

**Proven by:** `TestACaseNoteIsAttributedToItsAuthorAndTheReadIsRecorded`, `TestAnAnalystCannotActOnACase`.

## Supply chain

**What it gets:** whatever it can get into a build or a data file an endpoint trusts.

**What bounds it:** SIGNATURES ON EVERYTHING AN ENDPOINT LOADS — detector rule bundles, EDM/IDM indexes,
threat-intel feeds, FIM baselines. Each is verified against an operator public key BEFORE it is parsed,
and a bad signature refuses the WHOLE artifact rather than loading part of one. Reproducible builds
(`-trimpath`, `CGO_ENABLED=0`) are what make a release signature mean something.

**Proven by:** `TestATamperedEDMIndexIsRefused`, `TestAnEDMIndexSignedByTheWrongKeyIsRefused`,
`TestASignedBundleLoadsWithTheWorkersOwnLoader`, `TestATamperedIOCFeedIsRefusedWholesale`.

**Recorded honestly, because it is recent:** the *gateway* read its IOC feed UNVERIFIED until D297, while
the signed loader sat unused — so anything that could write that file decided what the gateway blocked,
and equally what it let through. Dropping the indicator that would catch you is the quieter attack. The
signing tool for detector rule bundles did not exist until D297 either: the worker verified an artifact
an operator had no way to produce.

## What this section does NOT cover

- **A malicious build of OpenShield itself.** Signing proves an artifact came from the release key; it
  says nothing about whether what that key signed is trustworthy.
- **The database as an adversary.** An attacker with write access to Postgres is bounded by the hash
  chain for the ledger, and NOT bounded at all for the aggregate stores — incidents, alerts and
  configuration are ordinary rows.
- **Denial of service.** Fail-open is a sanctioned bypass (above), and an attacker who can make the
  platform slow can make it permissive.
