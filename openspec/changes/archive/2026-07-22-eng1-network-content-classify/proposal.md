# ENG-1: network-content classification path (unblocks SMTP body DLP)

## Why

The D134 fix hard-codes "network event ⇒ skip content classification" — correct for DNS
(metadata-only), but an SMTP MESSAGE is a network event WITH content: the message body must reach
the sandboxed worker (D29/D35) to be classified for DLP. As-is, wiring the SMTP source would
silently no-op email-body classification. ENG-1 adds the missing branch, so SMTP body DLP has a
path to the worker. This is a blocking precondition for the SMTP source wiring (NIPS-3-SMTP), not
a follow-up.

## What Changes

- **A content branch in `classifyStage`**: for a non-file event, if a `ContentResolver` yields
  bytes (an SMTP body), classify them in the worker via inline `ClassifyRequest_Content`; otherwise
  the event is metadata-only (DNS/HTTP/exec/USB) and gets an empty classification (D134 preserved).
  A pathless file event still errors.
- **The content stays OUT of the Event** (D10): the connector buffers the body and the engine
  forwards it to the worker over IPC. The engine never PARSES it — the RCE-prone parsing stays in
  the worker sandbox (D29). The worker already accepts inline `Content` (no worker change).
- **`Engine.SetContentResolver`**: installs the source of out-of-band content, defaulting to none
  (so all existing behavior — files, DNS metadata — is unchanged). The SMTP source will provide it
  when wired.

No core change: the seam is an engine-level `contentHolder` shared with the classify stage; the
frozen `Dispatcher`/`State`/`Stage` and the D10/D29 boundary are untouched.

## Impact

- Affected specs: `endpoint-engine`
- Affected code: `internal/engine/engine.go` (ContentResolver + branch + SetContentResolver).
- Not in scope (stated): the SMTP source that fills the resolver (NIPS-3-SMTP); streaming/partial
  classification of very large bodies (the worker's existing max-bytes bound applies); response-body
  or multipart/gzip decode (NIPS-4/DLP-8).
