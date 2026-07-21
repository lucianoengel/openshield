# pattern-classifier delta

## ADDED Requirements

### Requirement: The classifier detects secrets and credentials with structural validators
The classifier MUST detect private keys, cloud access keys, JSON Web Tokens, and
vendor-prefixed API tokens, each via a candidate pattern paired with a real validator — a
PEM private-key framing (and NOT a public key), a published key-id prefix with the correct
charset and length, a JWT whose header base64url-decodes to a JOSE header, and a token with
a distinctive vendor prefix above a length floor. A benign look-alike (a public key, a
non-JOSE three-part string, a wrong-charset key-shaped word, a truncated prefix) MUST NOT
be reported. A secrets hit MUST carry high confidence, reflecting the structural evidence.

#### Scenario: A real secret is detected and a look-alike is not
- **WHEN** the classifier scans content containing a private key, an AWS key, a JWT, or a vendor token
- **THEN** the matching secrets detector fires at high confidence, while a public key, a non-JOSE token, or a wrong-charset look-alike reads clean
