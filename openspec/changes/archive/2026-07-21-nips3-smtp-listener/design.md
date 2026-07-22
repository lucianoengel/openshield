## Context

D102 gave the SMTP transcript parser; D108/D128 gave the UDP listeners. SMTP is a stateful TCP
session, so its listener must speak enough of the dialogue for a client to deliver a message.

## Goals / Non-Goals

**Goals:** a capture server that receives a real SMTP session and parses it to a sink.

**Non-Goals:** relaying mail (it is not an MTA); STARTTLS; pipeline/worker wiring; AUTH.

## Decisions

**A minimal RESPONDING server, not a passive reader.** A real SMTP client waits for a 220
greeting and a response to each command; a passive read-until-close would hang it. So the
listener answers 220/250/354/221 enough to drive the client through EHLO→MAIL→RCPT→DATA→QUIT,
accumulating the transcript, then parses it with the D102 parser on session end. The happy-path
test uses Go's net/smtp, so the dialogue responses are proven end to end.

**Capture, not relay.** It does not forward the mail — it is a monitoring/DLP endpoint. Real
deployment sits inline (an MTA relay/proxy) or receives a copy; the capture + parse is the
reusable core.

**Bad session dropped and counted.** A session that does not parse (no sender/recipient,
unterminated DATA) is dropped with the count exposed — never delivered as a partial message,
never fatal to the listener (D17/D28).

## Risks / Trade-offs

- **Not a full MTA** — no relay, no AUTH, no STARTTLS, no size negotiation beyond a bound. It
  captures; a production inline deployment is the data-plane follow-up.
- **Sink not yet the pipeline** — the message goes to a callback; worker-classify + policy is a
  follow-up, kept separate so the listener is proven on its own.
