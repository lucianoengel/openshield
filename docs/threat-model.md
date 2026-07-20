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
