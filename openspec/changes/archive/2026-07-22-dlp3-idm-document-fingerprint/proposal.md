## Why

EDM matches structured data — a specific account number, a record's fields. But sensitive material is
often an unstructured *document*: a contract, a board deck, a source file, a patient report. IDM (Indexed
Document Matching) fingerprints such documents and detects when content contains a substantial chunk of
one — even reformatted or excerpted — so pasting a paragraph of a confidential document into an email or
uploading a copied source file is caught. This is the "I" of DLP-3's EDM/IDM/OCR, and it completes the
fully-buildable core of DLP-3.

## What Changes

- A document index: shingle each sensitive document into overlapping word k-grams, fingerprint the
  shingles (hashes only, no raw text), and store per-document shingle fingerprints — so the scanner can
  tell how much of a fingerprinted document appears in content.
- An IDM detector: shingle the content, tally per-document shingle matches, and fire when a document
  reaches a threshold FRACTION of its shingles — reported as a distinct `DETECTOR_TYPE_IDM`.
- Serialization (ship the index into the sandbox, ADR-9) and worker wiring, composing with EDM and the
  built-in detectors.

## Capabilities

### New Capabilities
- `document-fingerprinting`: detect content that contains a substantial portion of a fingerprinted
  sensitive document (excerpt or reformat tolerant), via k-gram shingle matching over a k-anonymized
  index — the unstructured-document counterpart to EDM.

### Modified Capabilities
<!-- none -->

## Impact

- **Code:** `DETECTOR_TYPE_IDM` (proto); `internal/classify` gains a `DocumentIndex` (shingle
  fingerprints), an IDM detector, serialize/load, `Classifier.AddIDM`; the worker loads a document index
  from an env. Proven: content containing enough shingles of a fingerprinted document matches (including
  an excerpt and a reformat); unrelated text does not; a short/low-overlap snippet below the fraction
  does not; the serialized index carries no raw document text.
- **Scope note (honest):** the index stores ALL shingles of each document; **winnowing / min-hash**
  (selecting a shingle subset to bound index size for very large corpora) is a scale refinement, noted.
  Shingle hashes, like EDM's, are brute-forceable for very short/low-entropy shingles — mitigated by the
  k-gram width (a 5-word shingle is high-entropy). **OCR** (extracting text from images before matching)
  is the remaining DLP-3 piece and needs an OCR engine dependency (a separate decision).
