## Context

D100 built the signed-rule verification (fail-closed, all-or-nothing) but nothing loaded a
bundle. HON-1 is the wiring: the worker reads a configured bundle and merges it.

## Goals / Non-Goals

**Goals:** the worker loads verified signed rules when configured, fail-closed, availability
preserved.

**Non-Goals:** a signing tool; hot-reload; per-rule routing.

## Decisions

**Fail-closed on the rules, available on the worker.** A misconfigured key or an
unverified/unreadable bundle loads NO custom rules (D100 returns nothing on a bad bundle), but
the worker still classifies with the built-in detectors — refusing to start would take down
classification entirely over a bad optional bundle. The security property (no unverified rule
loaded) is guaranteed by LoadSignedRules; the worker's own error branches only log and
degrade to built-ins.

**Configured, not default.** No bundle path → built-ins only, exactly as before. The feature
is opt-in via OPENSHIELD_RULES_BUNDLE + OPENSHIELD_RULES_PUBKEY.

## Risks / Trade-offs

- **A tampered bundle silently degrades to built-ins** (with a loud log). Correct: it must not
  load unverified rules, and it must not stop classifying. The log is how an operator notices.
- **No signing tool yet** — an operator signs via the API; a provision subcommand is a small
  follow-up.
