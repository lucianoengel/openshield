# pattern-classifier (delta)

## MODIFIED Requirements

### Requirement: The classifier detects secrets and credentials with structural validators
The classifier MUST detect private keys, cloud access keys, JWTs, and vendor API tokens using a
candidate pattern paired with a real validator (a PEM frame, a prefixed key id, a decodable JOSE
header, a distinctive vendor prefix), never a bare regex, so a look-alike string does not trip it.
The vendor-token detector MUST recognize the distinctive prefixes of the common secret formats —
including GitHub, Slack, Google, OpenAI/Anthropic, Stripe (live and restricted), GitLab, npm,
SendGrid, and Twilio — with a body length or charset floor that rejects truncated look-alikes, and
MUST report these at a high, calibrated confidence reflecting how distinctive the prefix is.

#### Scenario: A benign look-alike does not trip a secret detector
- **WHEN** the classifier scans a three-dotted non-JOSE token, an AKIA-shaped word, a public-key line, or a truncated or wrong-prefix vendor-token look-alike
- **THEN** none of the secret detectors fire

#### Scenario: A real vendor token is detected
- **WHEN** the classifier scans text containing a real vendor-prefixed token (GitHub, Slack, GitLab, npm, SendGrid, Stripe restricted, Twilio, …)
- **THEN** the API-token detector fires at its calibrated confidence
