# Security Policy

OpenShield is security software that runs privileged code on endpoints. Vulnerability reports
are welcome and taken seriously.

## Reporting

Report privately via [GitHub Security Advisories](https://github.com/lucianoengel/openshield/security/advisories/new).
Please do not open a public issue for a suspected vulnerability.

## What you can expect — stated honestly

This project currently has **one maintainer**, who does not write code personally (see
[`CONTRIBUTING.md`](CONTRIBUTING.md)). The commitments below are what can actually be met, not
what sounds reassuring:

- **Acknowledgement within 5 business days.**
- **No fix-time guarantee.** You will get an honest assessment of severity and a realistic
  estimate, or an admission that it will be slow.
- If a report cannot be triaged promptly, you will be told so rather than left in silence.
- Coordinated disclosure preferred; **90 days** is a reasonable default and we will not ask you
  to wait longer without explaining why.
- Credit given unless you prefer otherwise.

An aspirational SLA that gets missed is worse than a slow one that is kept. If these terms are
not acceptable for your disclosure policy, that is legitimate — say so in your report.

CVE issuance goes through a coordinating CNA rather than this project directly.

## Scope

**In scope:** the agent (especially the privileged process and the sandbox boundary between it
and the content parser), the control plane, the audit ledger's integrity properties, policy
evaluation, and anything that lets a lower-privileged actor influence a higher-privileged one.

**Especially interesting:** anything that escapes the unprivileged parser worker into the
privileged process; anything that forges, suppresses or rewrites audit entries; anything that
makes a `Decision` differ from what the policy specifies.

**Not vulnerabilities** — these are documented design limits, see
[`docs/threat-model.md`](docs/threat-model.md):

- A user with root on their own machine disabling or bypassing the agent. Host agents cannot
  defend against the administrator of the host. The goal is tamper-*detection*.
- Classification missing deliberately obfuscated content (encrypted, screenshotted, retyped).
  The design centre is the careless insider.
- Fail-open behaviour under classifier timeout. This is deliberate — a stalled agent must not
  hang the machine — and every occurrence is audited. Reports that *fail-open triggers without
  being audited*, or that budgets can be evaded, **are** in scope.
- The audit log not being "tamper-proof". The claim is tamper-*evident* with forward integrity
  between anchors. Breaking forward integrity, or tampering that goes undetected between
  anchors, **is** in scope.

## Supply chain

Hub packs will use ed25519 per-author signing with pinned keys and fail-closed verification on
stale metadata. **Offline revocation is an unsolved problem** — the propagation window equals
the sync interval. This is a documented limitation, not an oversight; reports that narrow the
window are welcome.
