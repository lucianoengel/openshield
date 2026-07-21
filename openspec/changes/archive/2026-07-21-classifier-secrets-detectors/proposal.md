## Why

The classifier had four detectors (CPF, card, SSN, email) — credible for PII but blind to
the secrets that dominate real exfiltration incidents: private keys, cloud credentials,
tokens. Phase D2 adds structural secrets detectors. Unlike PII these are unambiguous
artifacts (a PEM block, a prefixed cloud key, a decodable JWT), so a validated hit is
strong, low-false-positive evidence — and a leaked key is the ideal inline-BLOCK candidate
(D94).

## What Changes

- Four detectors in `internal/classify` (default classifier): `privateKey` (PEM blocks),
  `awsAccessKey` (prefixed 20-char key id), `jwt` (structural — header base64url-decodes
  to a JOSE header), `apiToken` (vendor-prefixed: GitHub/Slack/Google/OpenAI/Stripe). New
  `DetectorType` enum values PRIVATE_KEY/AWS_ACCESS_KEY/JWT/API_TOKEN.

## Capabilities

### Modified Capabilities
- `pattern-classifier`: adds structural secrets/credential detectors with real validators.

## Impact

- `proto/…/classification.proto` (+4 enum values, regenerated); new
  `internal/classify/secrets.go`; `docs/decisions.md` D96.
- Proven: each detector fires on a real secret (a PEM private-key block, an
  AKIA-prefixed AWS key, a genuinely-minted JWT, GitHub/Slack tokens) at high confidence;
  benign look-alikes (a PUBLIC key, an SSH public-key line, a non-JOSE three-part token,
  an AKIA-shaped word with the wrong charset, a truncated `sk-`) read CLEAN. Guards
  mutation-tested (JWT-skips-header-check; private-matches-public; AWS-charset-relaxed).
- NOT in scope (stated): document-structure parsing (PDF/DOCX/XLSX in the worker, D1 —
  the next Phase-D increment); health-data/IBAN/passport/keyword detectors (D2 remainder);
  admin-authorable detectors + signed distribution (D3); ML/EDM (D4). Each detector pairs
  a candidate regex with a real validator (the CPF/Luhn discipline), never a bare regex.
  Runs in the sandboxed worker (D35); adds no parser to the privileged agent (D72).
