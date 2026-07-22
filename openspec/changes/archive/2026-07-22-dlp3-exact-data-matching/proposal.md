## Why

Every DLP detector so far is a *format* detector — it flags anything shaped like a credit card or an
SSN. That catches careless disclosure of *a* card number, but not the exfiltration of *this company's
actual customer records*: a specific list of account numbers, member IDs, or order references that are
sensitive precisely because they are real. Exact Data Matching (EDM) is the enterprise-DLP capability
that closes this — fingerprint the sensitive dataset and detect when one of its actual values appears in
a flow. This is the first DLP-3 increment (ADR-9: server-side / a signed index into the sandbox; content
and fingerprints never leave the endpoint).

## What Changes

- An EDM index: a bloom filter over normalized fingerprints of the sensitive values in an operator
  dataset. It is **k-anonymized by construction** — it stores only hashes in a bloom filter, never the
  raw values — so the index can be shipped into the sandboxed worker without the dataset leaving the
  operator's control (ADR-9, D10/D11).
- An EDM detector that tokenizes content, normalizes each candidate value, and flags those present in
  the index — detecting a *specific* sensitive value, not just its format.
- A distinct `DETECTOR_TYPE_EDM` so a policy can route on an exact-data match differently from a format
  hit, and an index builder that skips low-entropy/short tokens (which would over-match).

## Capabilities

### New Capabilities
- `exact-data-matching`: detect a flow carrying an actual value from the operator's fingerprinted
  sensitive dataset, via a k-anonymized bloom index — matching specific data, not only its shape.

### Modified Capabilities
<!-- none -->

## Impact

- **Code:** `DETECTOR_TYPE_EDM` (proto); `internal/classify` gains an EDM index (bloom filter, build +
  serialize/load) and an EDM detector, addable to the classifier when an index is configured; the worker
  loads a serialized index. Proven: indexed values are detected in content; non-indexed distinctive
  values are not (within the bloom's bounded false-positive rate); low-entropy tokens are not indexed;
  the serialized index round-trips and never contains a raw value.
- **Scope note (honest):** this matches **single values** against the fingerprint set with a bloom
  filter, whose false-positive rate is bounded and measured (not zero). **Multi-cell record correlation**
  — requiring several fields of the *same* record to co-occur, which is what drives enterprise EDM's very
  low FP — is the next increment. **IDM (indexed document matching)** and **OCR** (the rest of DLP-3) are
  separate follow-ups. The index is built and loaded from a file here; **signing** the index (ADR-9's
  tamper-evidence for the shipped index) is a noted follow-up. The index is k-anonymized (hashes only),
  so it is safe to ship even before signing.
