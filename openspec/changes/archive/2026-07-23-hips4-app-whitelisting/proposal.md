## Why

HIPS-3 (D224) gave the endpoint inline exec control via a **deny-list** — block named-bad binaries. The
stronger, enterprise-grade control is the inverse: **application whitelisting** (default-deny) — only
operator-approved binaries may execute, everything else is refused. A deny-list stops known bad; a
whitelist stops the unknown (a dropped malware binary, a living-off-the-land tool the operator didn't
anticipate) because it isn't on the approved list. This reuses the exec-permission producer and watchdog
already proven on the VM (D224) — the only new logic is the allowlist decision.

## What Changes

- **Allowlist (default-deny) mode** on the inline exec evaluator: when an allowlist is configured, a
  resolved exec whose path or basename is NOT allowlisted is **blocked**. The deny-list and behavioral
  gate still apply FIRST — they can block an *allowlisted* binary (a compromised-but-approved tool), so
  deny wins over allow.
- **Safe on an unidentifiable exec:** an exec whose path cannot be resolved is **allowed** (we cannot
  verify it against the allowlist; availability over a false block, D17) — a strict deny-unknown mode is
  a documented follow-up. The agent's own execs are already exempt via the watchdog self-PID rule.
- **Wiring:** `OPENSHIELD_EXEC_ALLOW` (an allowlist file, same `path`/`basename` format as the deny-list)
  turns on whitelisting; without it, the deny-list-only behavior (D224) is unchanged.

## Capabilities

### New Capabilities
<!-- none — extends the inline-prevention capability (HIPS-3/4 exec control). -->

### Modified Capabilities
- `inline-prevention`: add application whitelisting — when an allowlist is configured, an execution not
  on it is refused inline (default-deny), with the deny-list and behavioral checks still able to block an
  allowlisted binary.

## Impact

- **Code:** `internal/agent/execmon` (`DenyEvaluator` gains allowlist fields + default-deny logic);
  `cmd/openshield-agent` (`OPENSHIELD_EXEC_ALLOW` wiring). No proto, no migration, no new dependency; the
  privileged binary stays parser-free (the allowlist is a plain file via the existing `LoadDenyList`).
- **Testing:** unit tests (allowlisted → allow; not-allowlisted → block; deny wins over allow;
  unresolved path → allow; no allowlist → D224 behavior); a gated real-kernel test on the VM — a
  non-allowlisted binary is kernel-refused, an allowlisted one runs.
- **Deferred:** a strict deny-unknown-path mode; content-hash / signature allowlisting (not just
  path/basename — a renamed binary at an allowlisted path would pass; the deny-list's basename check and
  the behavioral gate partially cover this); allowlist distribution/signing (the operator manages the
  file, like the deny-list).
