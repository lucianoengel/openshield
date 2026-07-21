## Context

The DNS connector (D101) established the Phase-C shape: a pure protocol parser + Event
producer, sockets deferred. SMTP follows it, with the added property that the message BODY
is the classification target (not just metadata).

## Goals / Non-Goals

**Goals:** parse an SMTP session to envelope + body; body reaches classification; recipient
domain is policy metadata; no core change.

**Non-Goals:** the socket listener/MTA (external-gated); MIME/attachments; STARTTLS.

## Decisions

**Body is classified, envelope is metadata — and addresses stay out of the Event.** The
DATA body (where the PII lives) is returned for the sandboxed worker to classify (D72), NOT
placed in the Event (D10/D29). Only the recipient DOMAIN rides the Event (the destination a
policy acts on); full addresses are PII and are deliberately withheld from the Event, even
though the worker's email detector may find them in the body.

**Dot-unstuffing and the lone-dot terminator, per RFC 5321.** The DATA block ends at a line
containing only ".", and a client line beginning with ".." is un-stuffed to a literal ".".
Getting this wrong either truncates the body (missing content) or captures past the message
(false content) — both are detection errors, so the parser handles both and the test
asserts the double-dot is actually removed (not merely that a single-dot substring exists).

**Reject an incomplete session.** No sender, no recipient, or an unterminated DATA block is
an error, never a partial message treated as complete (D17) — a truncated capture must not
read as a clean, fully-scanned message.

## Risks / Trade-offs

- **One body blob, no MIME decomposition yet.** A base64 MIME attachment is classified as
  its encoded bytes, not decoded — the document extractors (D97/D99) would compose here as a
  follow-up. The envelope + plaintext-body coverage is the honest first step.
- **No live capture.** Parser + producer only; the MTA/socket side is external-gated.
