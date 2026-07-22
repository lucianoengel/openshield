# DLP: additional modern secret-token prefixes

## Why

The API-token detector recognized GitHub, Slack, Google, OpenAI/Anthropic, and Stripe live keys,
but not several other high-value secret formats that leak into code and documents: GitLab PATs,
npm automation tokens, SendGrid keys, Stripe RESTRICTED keys, and Twilio API SIDs. Each has a
distinctive prefix, so recognizing it is high-value and low-false-positive.

## What Changes

- **The `apiToken` detector regex gains five alternatives**: GitLab (`glpat-`), npm (`npm_` +
  36), SendGrid (`SG.x.y`), Stripe restricted (`rk_live_`), and Twilio (`SK` + 32 hex). Each is a
  distinctive prefix plus a body length/charset floor that filters truncated look-alikes. No new
  detector type — these are more `DETECTOR_TYPE_API_TOKEN` prefixes, at the same confidence (0.90).

This modifies the `pattern-classifier` capability's secrets requirement. No enum or contract change.

## Impact

- Affected specs: `pattern-classifier`
- Affected code: `internal/classify/secrets.go` (the `apiTokenRe` regex).
- Not in scope (stated): entropy scoring of the secret body (the prefix is the signal here);
  Stripe/GitLab TEST-mode keys (lower sensitivity than live/restricted); provider-side liveness
  verification (the classifier never makes network calls).
