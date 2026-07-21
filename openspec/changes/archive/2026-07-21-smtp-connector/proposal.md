## Why

Email is a primary data-exfiltration channel, and it did not enter the pipeline. Phase C
(network breadth) adds an SMTP-message connector so outbound mail flows through the SAME
pipeline as file, HTTP, and DNS events — the message body is classified for PII/secrets and
the envelope (recipient domains) is metadata for egress policy.

## What Changes

- `EVENT_KIND_SMTP_MESSAGE` (additive enum).
- `internal/connectors/smtp`: `ParseSession` (pure SMTP transcript parser — envelope
  MAIL FROM / RCPT TO, DATA body with dot-unstuffing, bounded, rejects malformed sessions);
  `RecipientDomains`; `ToEvent` (NetworkSubject Event, recipient domain as metadata — full
  addresses kept OUT); `Message.Body` for worker classification.

## Capabilities

### Added Capabilities
- `smtp-connector`: outbound SMTP messages enter the pipeline; the body is classifiable and
  the recipient domain is policy metadata.

## Impact

- `proto/…/event.proto` (+1 enum value, regenerated); new `internal/connectors/smtp`;
  `docs/decisions.md` D102.
- Proven with a real SMTP transcript: envelope (from, two recipients, subject) extracted;
  DATA body captured with dot-unstuffing (a client "..line" becomes literal ".line", and
  the double dot is asserted GONE) and NOT captured past the "." terminator; the Event
  carries the recipient DOMAIN (partner.example), never a full address or the body; and the
  extracted body reaches the classifier — a CPF in the email is DETECTED (email DLP end to
  end, minus sockets). Malformed sessions (no sender, no recipient, unterminated DATA,
  empty) rejected. Guards mutation-tested (DATA-terminated; no-recipient; dot-unstuffing;
  domain-not-full-address).
- NOT in scope (stated): the port 25/587 socket listener / MTA interception (the I/O side,
  external-gated like the transparent DNS listener and B2); MIME/attachment decomposition
  (the body is classified as one blob; per-attachment parsing reuses the D97/D99 document
  extractors — a follow-up); TLS (STARTTLS) termination; SMTP responses. The body is
  classified in the worker (D72), never placed in the Event; envelope addresses are kept out
  of the Event to avoid leaking PII (D10/D29). No core interface changed (D26/D69 pattern).
