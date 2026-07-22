# Tasks — DLP-5 compliance packs
- [x] pci/hipaa/gdpr.rego packs keyed on the regulation's detector types; observe-only ALERT.
- [x] Embed packs; policy.NewPack(name) + policy.Packs(); unknown -> error.
- [x] Engine + gateway select via OPENSHIELD_POLICY_PACK (else default); unknown aborts startup.
- [x] Test: each pack alerts in-scope, allows out-of-scope; unknown errors; Packs() lists 3.
- [x] make all clean; docs D165; sync; archive; commit; push; memory.
