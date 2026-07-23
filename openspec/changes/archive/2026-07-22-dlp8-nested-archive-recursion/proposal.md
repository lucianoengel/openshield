## Why

The DLP classifier extracts text from a recognized Office document (OOXML) or a PDF before running
detectors — but a GENERAL archive is a blind spot. A sensitive file inside a plain `secrets.zip`, or a
`.docx` inside a `.zip`, or a zip-in-a-zip, is never extracted: `extractOOXML` returns false (no OOXML
text members), so the classifier scans the raw DEFLATE-compressed bytes and sees noise. So the simplest
evasion — **put the sensitive file in a zip (or double-zip it)** — defeats content detection entirely.
This is DLP-8's "nested-archive recursion (stops at one level today)".

## What Changes

- **A recursive content extractor** (`internal/classify`): a general ZIP archive has EVERY member
  extracted and classified, and a member that is itself a container (an OOXML doc, a PDF, or another
  ZIP) is recursed into — so a sensitive value in a plain zip, or nested N levels deep, is visible to
  the same detectors. Bounded against a decompression bomb: a SHARED byte budget across the whole
  recursion (a zip-bomb-in-a-zip cannot blow past it), a depth cap, and the existing per-entry/entry-
  count caps.
- **`Classify` runs the recursive extractor** in place of the single-level OOXML/PDF check — a
  non-container still scans as-is (a mis-detection degrades to "scan raw", never "scan nothing"), an
  Office doc still yields clean OOXML text (extractOOXML is tried first, before the general-zip path).

No new detectors — the SAME detectors now see content that was previously hidden inside archives.

## Capabilities

### New Capabilities
<!-- none: this deepens the existing pattern-classifier / DLP content extraction. -->

### Modified Capabilities
- `pattern-classifier`: content inside a general (non-OOXML) ZIP, and inside nested archives, is now
  extracted and classified rather than scanned as opaque compressed bytes.

## Impact

- `internal/classify/documents.go`: `extractContent` (recursive, budget-shared) + `extractZipArchive`
  (all-members, recursing); `Classify` calls `extractContent`.
- Bounds reuse the existing `maxExtractBytes`/`maxZipEntries`/`maxEntryBytes` + a new depth cap.
- No proto/core change, no new dependency, runs entirely in the sandboxed worker (the parser surface
  the D29/D35 split exists for). RTF/legacy `.doc` and tar/gzip are separate DLP-8 follow-ons.
