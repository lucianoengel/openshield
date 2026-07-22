# DLP-5: compliance policy packs (PCI / HIPAA / GDPR)

## Why

The classifier grew broad detector coverage (card, ABA, SSN, health, NPI, NHS, IBAN, email, phone,
SIN, EIN, …), but the only shipped policy was one hand-written `default.rego` that alerts on CPF and
credit-card. So an operator wanting a PCI, HIPAA, or GDPR control had to author Rego themselves —
the detector breadth was there but not usable as a compliance control out of the box.

## What Changes

- **Three ready-made compliance packs** as embedded Rego modules, each keyed on the detector types
  in that regulation's scope and observe-only (ALERT, never BLOCK):
  - **PCI** — payment-card + bank-account data (credit card, ABA routing, IBAN).
  - **HIPAA** — protected health information (health-data, NPI, UK NHS, SSN).
  - **GDPR** — personal data (email, phone, IBAN, SIN, EIN, SSN, CPF).
- **`policy.NewPack(name)`** loads a pack by name; **`policy.Packs()`** lists them. An unknown pack
  is an ERROR, never a silent fallback to a permissive policy.
- **The engine and gateway select a pack** via `OPENSHIELD_POLICY_PACK`, else the observe-only
  default; an unknown pack aborts startup. The pack's id/version is stamped on each Decision.

## Impact

- Affected specs: `policy-evaluation`
- Affected code: `internal/policy/packs/{pci,hipaa,gdpr}.rego`, `internal/policy/embed.go`,
  `cmd/openshield-engine/main.go`, `cmd/openshield-gateway/main.go`.
- Not in scope (stated): per-regulation ENFORCEMENT actions (packs ALERT; blocking/quarantine is the
  operator's separate opt-in, consistent with observe-first D1); jurisdiction/asset-tier refinement
  of the packs (a starting template, tunable via the signed custom-rule surface, HON-1); mapping a
  pack to specific data-residency or retention obligations (a policy-content follow-up).
