## Context

`execmon.DenyEvaluator` (D224) implements `watchdog.Evaluator`: it blocks a resolved exec whose path or
basename is on the deny-list, or whose `behavioral.Analyze` score exceeds a floor, else allows. It runs
in the parser-free privileged agent, decides within the permission budget with no IPC, and is driven by
the fanotify exec-permission producer (proven on the VM). Whitelisting adds the inverse rule.

## Goals / Non-Goals

**Goals:** default-deny — only allowlisted binaries run when an allowlist is configured; deny-list and
behavioral still block first (deny > allow); safe on an unidentifiable exec; parser-free; no new deps.

**Non-Goals:** strict deny-unknown-path; content-hash/signature allowlisting; allowlist signing. Deferred.

## Decisions

1. **Order: deny → behavioral → allowlist → allow.** The evaluator checks the deny-list and behavioral
   gate FIRST — they can block an *allowlisted* binary (a legitimately-installed tool that turns
   malicious, or a LOLBin). Only then, if an allowlist is configured and the resolved exec is NOT on it,
   block (default-deny). This makes deny strictly stronger than allow, which is the safe composition.

2. **Allowlist is active iff non-empty.** `OPENSHIELD_EXEC_ALLOW` loads paths/basenames via the existing
   `LoadDenyList` parser (same `/abs/path` vs `basename` grammar). An empty/absent allowlist leaves the
   evaluator in D224's deny-list-only mode — whitelisting is opt-in, and configuring it is an explicit,
   consequential operator choice (default-deny can break a host if the list is incomplete).

3. **An unresolved path is allowed (fail-open on identity).** If the producer could not resolve the exec
   path (`e.Path == ""`), the evaluator cannot verify it against the allowlist — it allows (availability
   over a false block, D17), same as the deny-list already treats an unknown path. In practice the
   producer resolves via `/proc/self/fd`, which is reliable; a strict deny-unknown mode is a follow-up.
   The agent's own execs are exempt earlier via the watchdog self-PID rule, so whitelisting cannot
   deadlock the agent against itself.

4. **Parser-free preserved.** The allowlist is a plain file loaded by `LoadDenyList` (no corev1/json/OPA)
   — the privileged binary's `check-agent-deps` guarantee is unaffected.

## Risks / Trade-offs

- **Default-deny can break a host with an incomplete allowlist.** This is inherent to whitelisting; it is
  opt-in and the operator owns the list. The watchdog fail-open (on evaluation error/timeout) and the
  self-PID exemption bound the blast radius, and an unresolved-path exec is allowed rather than blocked.
- **Path/basename allowlisting, not content.** A malicious binary placed AT an allowlisted path (or named
  an allowlisted basename) would pass. The deny-list basename check and the behavioral gate partially
  mitigate; content-hash allowlisting is a deferred hardening.
- **Deny-wins composition** means an operator who allowlists a binary can still have it blocked by the
  deny-list/behavioral — intended (defense in depth), and documented so it is not surprising.
- **The allowlist MUST include the dynamic loader and interpreters.** The kernel raises
  FAN_OPEN_EXEC_PERM for the dynamic loader (`ld-linux-*.so`) and any script interpreter, not only the
  main binary — verified on the VM (the loader event is a separate exec-permission event). A default-deny
  allowlist that omits the loader breaks every dynamically-linked binary. An operator allowlist must
  therefore include `/lib64/ld-linux-*` (and `/bin/bash` etc. for scripts). This is inherent to
  exec-permission whitelisting and is documented; a future refinement could auto-exempt the loader, but
  that is itself a trust decision left explicit for now.
