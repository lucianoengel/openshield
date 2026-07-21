## Context

The four existing detectors follow one shape: a candidate regex + a real validator
(check digits, Luhn, structural rules). Secrets fit the same Detector interface; the
validators differ (structural framing, prefix schemes, header decoding).

## Goals / Non-Goals

**Goals:** high-confidence, low-FP secrets detection (private keys, cloud keys, JWTs,
vendor tokens) via the existing Detector interface.

**Non-Goals:** document parsing; ML; a rule-authoring/distribution surface; exhaustive
vendor coverage (a representative, high-signal set).

## Decisions

**Validator, never a bare regex (the CPF/Luhn discipline).** A private key is validated by
its `BEGIN … PRIVATE KEY` framing (and NOT `PUBLIC KEY`); an AWS key by its published
prefix set + 16 base32 chars; a JWT by base64url-decoding the header and requiring a JOSE
header (a JSON object naming an `alg`) — signature NOT verified (no key; the goal is to
tell a real token structure from a coincidental three-dotted string); a vendor token by a
distinctive prefix + a length floor. Each rejects look-alikes, keeping FP low.

**High confidence, because the evidence is structural.** These sit at 0.85–0.98 —
higher than PII patterns — because the artifacts are unambiguous. That makes a secrets hit
a strong inline-BLOCK candidate (D94): a leaked private key in a file is exactly what
inline prevention should stop.

**No JSON parser in the classifier for the JWT check.** The JOSE-header test is a substring
check on the decoded header bytes (`{` … `"alg"`), avoiding an `encoding/json` dependency
in the classify package — keeping the detector's dependency surface minimal even though it
runs in the sandboxed worker.

## Risks / Trade-offs

- **Vendor coverage is representative, not exhaustive.** New token schemes appear
  constantly; this is a high-signal starter set, extensible by adding a detector. An
  admin-authorable detector surface (D3) is the general answer, deferred.
- **A base64/PEM body is not cryptographically validated.** The framing/prefix is the
  signal; validating the key material would need parsing it (more RCE surface) for little
  FP gain given how distinctive the framing already is.
