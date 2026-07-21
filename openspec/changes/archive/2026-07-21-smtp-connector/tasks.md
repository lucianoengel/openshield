# Tasks — SMTP connector (D102)

## 1. Connector

- [x] 1.1 EVENT_KIND_SMTP_MESSAGE; regenerate.
- [x] 1.2 `internal/connectors/smtp`: ParseSession (envelope + DATA body, dot-unstuffing, lone-dot terminator, bounded, rejects malformed), RecipientDomains, ToEvent (domain-only metadata), Message.Body for classification.

## 2. Proof (real transcript; guards mutation-tested)

- [x] 2.1 **Test**: envelope + subject extracted; body dot-unstuffed (double dot asserted gone) and terminator-bounded; Event carries recipient domain not full address/body; the body reaches the classifier and a CPF is detected; malformed sessions rejected.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D102.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| DATA-terminated guard removed (if false) | an unterminated-DATA session is then accepted |
| no-recipient guard removed | a session with no RCPT TO is then accepted |
| dot-unstuffing removed | the body then retains the double dot (asserted absent) |
| recipient domain → full address | a full address then rides the Event (leak) |
