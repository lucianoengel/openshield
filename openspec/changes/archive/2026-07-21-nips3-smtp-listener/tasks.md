# Tasks — NIPS-3 SMTP capture listener (D129)

## 1. Listener

- [x] 1.1 smtp.Listener (Listen/Serve/Addr/Dropped): responding SMTP server (220/250/354/221), capture transcript, parse on QUIT/close, drop+count malformed (atomic), bounded body, clean shutdown, nil-sink refused.

## 2. Proof (real net/smtp client; guards mutation-tested; race-clean)

- [x] 2.1 **Test**: a real client's session is captured + parsed, the body reaches the classifier (CPF detected); a malformed session is dropped+counted; nil sink refused.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D129.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| nil-sink guard removed | Listen accepts a nil sink |
| deliver ignores parse error | a malformed session is then delivered (nil) / not counted |
| (no 354 to DATA) | the happy path hangs the real client → the message is never captured (dialogue responses are load-bearing) |
