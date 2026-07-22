## Why

Selecting a compliance pack silently disables protections. A pack is loaded by *replacing* the
default policy: `OPENSHIELD_POLICY_PACK` → `policy.NewPack` → `policy.New(ctx, …, packModule)` with
**only** that pack's Rego. The pack files omit the default's HIPS `behavioral_alert` rule and the
CPF/credit-card strong-detector alert, so **enabling PCI silently turns off behavioral process
alerting** and drops every detector outside the pack's scope. No test catches it because none
asserts the default protections survive pack selection — they don't. A compliance control that
quietly *removes* controls is worse than none. ADR-5 is the governing decision: compose, don't
replace.

## What Changes

- Compliance packs **compose with** the default policy instead of replacing it: the composed policy
  is `default + selected packs + optional operator custom rules`, evaluated together.
- Each module is a valid standalone `package openshield` with its own `decision` complete-rule, so
  they cannot be concatenated (that yields conflicting-value eval errors). Each is evaluated as its
  own prepared query over the same input, and their Decisions are combined **in Go** under a
  **most-restrictive-wins lattice over the data-plane verbs**: `ALLOW < ALERT < REDIRECT <
  ENCRYPT_LOCAL < QUARANTINE_LOCAL < BLOCK` (QUARANTINE outranks ENCRYPT).
- The process-control verbs `DENY_EXEC`/`KILL_PROCESS` are **not** in the lattice. A compliance
  **pack** that emits one is a hard composition error — a pack can never silently escalate to
  killing a process. The default/operator process axis is preserved: on a process event the
  default's behavioral `ALERT` outranks a pack's `ALLOW`, so behavioral alerting survives pack
  selection.
- The composed **bundle id/version** is stamped on every Decision (reusing `PolicyId`/`PolicyVersion`
  — no proto change), so the ledger records exactly which bundle applied.
- **BREAKING (behavioral, intended):** `OPENSHIELD_POLICY_PACK=pci` now *adds* PCI to the default
  instead of replacing it. New `OPENSHIELD_POLICY_PACKS` (comma-separated) and optional
  `OPENSHIELD_POLICY_CUSTOM` (a Rego file) compose additional modules.

## Capabilities

### New Capabilities
<!-- none — this refines an existing capability -->

### Modified Capabilities
- `policy-evaluation`: compliance packs compose with the default under a most-restrictive-wins
  data-verb lattice (they no longer replace it); a pack cannot emit a process-control verb; the
  composed bundle identity is stamped on the Decision.

## Impact

- **Code:** `internal/policy` — refactor `Stage` to hold N named prepared queries + a combine step
  (a single policy = a 1-member composite, behavior-identical); add `NewComposite(ctx, packNames,
  customModule)`; `embed.go` pack registry unchanged. `cmd/openshield-engine` and
  `cmd/openshield-gateway` rewired to compose (`OPENSHIELD_POLICY_PACK[S]` + `OPENSHIELD_POLICY_CUSTOM`).
- **No core/proto change** — the closed action set (D14), the restricted-capability engine (D34),
  determinism/replay (D27), and the D10/D29 content boundary are untouched.
- **Deployment:** operators who set `OPENSHIELD_POLICY_PACK` now get default + pack (more alerts,
  never fewer); documented as a migration note.
