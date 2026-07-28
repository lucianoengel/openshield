# The SMTP connector is complete, tested, and started by nothing

## Why

`internal/connectors/smtp` has a session parser, a capture listener with per-session size ceilings,
idle timeouts and a concurrency cap, an event producer, and a full unit-test suite covering all of
it. **No binary imports the package.** There is not even a configuration setting that could turn it
on. It cannot run in any deployment, however configured.

Meanwhile `README.md` says the gateway performs "live DNS + SMTP inspection", lists SMTP among the
network data plane's capabilities, and shows it as a source in the pipeline diagram. A reader
concludes email is inspected. It is not, anywhere.

The capability spec is honest about its own scope — it says the listener and MTA interception are "a
separate, privileged data-plane concern" — so the false claim lives in the README, not the spec. But
"the spec never promised it" does not make the README true, and the smaller honest fix is to make the
claim true rather than to retract a capability that is already built and tested.

This is the fourth instance of the shape D341 named, and the largest: there the missing piece was one
comparison; here it is an entire connector. It was found the same way — by asking the code graph for
exported symbols with no non-test caller, which is the check D341 proposed and this is the first run
of it.

## What Changes

- `OPENSHIELD_SMTP_LISTEN` — a bootstrap setting that binds the SMTP capture listener, empty
  disabling it, exactly as `OPENSHIELD_DNS_LISTEN` does for the DNS connector.
- An engine event source that feeds parsed messages into the same event channel the file watchers
  and the DNS connector use, so an email runs classify → policy → decide → audit like anything else.
- Integration coverage: a real SMTP session delivered to a live listener, asserted on the AUDIT ROW,
  with a body carrying a checksum-backed value so the classification path is exercised rather than
  only the parse.
- The README's claim is left standing because it becomes true. Nothing about the maturity percentage
  changes — this makes an existing claim honest, it does not add a capability.

## Impact

- Affected specs: `smtp-connector`
- Affected code: `internal/config/endpoint2.go`, `cmd/openshield-engine`
- No proto change: `EVENT_KIND_SMTP_MESSAGE` already exists and `smtp.ToEvent` already produces it.
- No migration. No new dependency.
- Observe-only (D1). The listener is an additional SOURCE; it is not an enforcement path and does not
  become one here.

## Honest limits, stated rather than discovered later

- **This is a CAPTURE listener, not an MTA.** It answers enough dialogue for a client to deliver, so
  it belongs behind a mail flow that is pointed at it deliberately — a journaling/archive target or a
  tap. Putting it in the path of production mail is a deployment decision with availability
  consequences this change does not address, and the startup line must say so.
- **It does not intercept anything by itself.** Nothing is redirected to it; an operator sends mail
  to it.
- **Plaintext.** STARTTLS/implicit TLS is not handled, so a session that negotiates TLS is not
  parsed. That bounds where this can usefully sit and is worth stating on the startup line too.
