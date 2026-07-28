# Design

## Symmetry with the DNS source, deliberately

`cmd/openshield-engine/dnssource.go` already establishes the shape: a small file that binds a
connector's listener and adapts its sink into the engine's event channel, with a monotonic flow id
and a send that races context cancellation so shutdown never blocks on a full channel.

`smtpsource.go` is the same file for SMTP. That symmetry is the point rather than a convenience —
two connectors that enter the pipeline differently would mean two ways for a source to be wrong, and
the engine already has one shape that works.

The listener yields a `*smtp.Message`; `smtp.ToEvent` already turns it into an
`EVENT_KIND_SMTP_MESSAGE` event carrying the envelope and the body. Neither function changes.

## Where the body is classified

Nowhere new. The event carries the body, the engine's existing pipeline hands it to the sandboxed
worker like any other content, and the classification comes back as `input.classification`. That is
the whole reason this connector produces an ordinary Event instead of its own verdict — D72 puts
attacker bytes in the worker, and an email body is exactly attacker bytes.

So no policy change is needed either: a checksum-backed PII hit in an email body alerts under the
existing default rule, because the rule is about the classification and not about where it came from.
That is the frozen pipeline's claim working, and the integration scenario is what demonstrates it
rather than asserting it.

## What the startup line has to say

Three things, because each is a way an operator can be wrong about what they just enabled:

- that it is a CAPTURE listener and not an MTA, so mail must be pointed at it deliberately;
- that it does NOT handle TLS, so a client that negotiates STARTTLS is not parsed;
- that it is observe-only.

This follows the discipline the plaintext syslog stream listener already uses, which announces that
its sender is unauthenticated. A listener whose limits are only in the documentation is a listener
whose limits will be discovered in production.

## Why not the gateway

The README places SMTP inspection in the gateway, and the gateway is where TLS interception lives, so
that is where a future in-path SMTP proxy belongs. This puts the capture listener in the ENGINE
because that is where the connector's shape already fits (an additional event source alongside file,
DNS and exec), and because an in-path MTA is a different and much larger change with availability
consequences — mail that cannot be delivered is worse than mail that is not inspected.

Stated here so the next person does not read the engine placement as an accident.

## The test's failure modes

The scenario speaks real SMTP to the listener and asserts on the ledger. Two ways it could lie:

- **A parse that never classified.** If the body carried nothing detectable, "an event was produced"
  would pass while the content path did nothing. The body carries a checksum-backed CPF, and the
  assertion is that the decision ALERTED — which requires the worker to have classified it.
- **A ledger carrying the body.** An email body in the audit trail is the same disclosure the DNS
  name was, so `assertLedgerCarriesNone` covers the sensitive value.
