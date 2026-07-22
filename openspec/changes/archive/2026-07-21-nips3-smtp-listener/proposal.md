## Why

NIPS-3 (P1, part). The SMTP parser (D102) is built and tested, but only the socket front-end
was missing, so it could not capture live email. This adds a minimal SMTP listener — a
capture server that drives a real client through the session and parses the captured
transcript — completing the connector-runnable trio (syslog D108, DNS D128, SMTP now) and
making email DLP runnable end to end.

## What Changes

- `smtp.Listener` (`Listen`, `Serve`, `Addr`, `Dropped`): a TCP server that answers the SMTP
  dialogue (220/250/354/221) enough for a real client to complete a session, accumulates the
  transcript, parses it (D102) on QUIT/close, and delivers the message to a sink. A session
  that fails to parse is dropped and COUNTED; a nil sink is refused; bounded body; clean
  context-cancel shutdown.

## Capabilities

### Modified Capabilities
- `smtp-connector`: a runnable SMTP capture server receives and parses live email sessions.

## Impact

- New `internal/connectors/smtp/listen.go`; `docs/decisions.md` D129.
- Proven with a REAL client (Go net/smtp) over a real TCP session: the listener captures the
  message, parses the envelope, and the captured body reaches the classifier — a CPF in the
  email is detected (email DLP runnable end to end); a malformed session (no envelope) is
  dropped and counted, never delivered; a nil sink is refused. Race-clean. Guards
  mutation-tested (nil-sink; deliver-ignores-parse-error). The dialogue responses are proven
  load-bearing by the happy path (a real client completes only if each step — including the 354
  DATA prompt — is answered).
- NOT in scope (stated): the privileged port 25/587 bind / MTA interception (a deployment
  concern — the address is configurable, runs unprivileged on a high port); relaying the mail
  (this is a CAPTURE endpoint, not an MTA); STARTTLS; wiring the message body to the sandboxed
  worker + pipeline (the sink is a callback; classifying via the worker with a policy/decision
  is a follow-up, kept separate so the listener is proven on its own); AUTH.
