# Tasks — NIPS-3 DNS UDP listener (D128)

## 1. Listener

- [x] 1.1 dns.Listener (Listen/Serve/Addr/Dropped): UDP bind, parse each datagram to a sink, drop+count malformed (atomic), clean ctx-cancel shutdown, nil-sink refused.

## 2. Proof (real UDP socket; guards mutation-tested; race-clean)

- [x] 2.1 **Test**: two valid queries arrive parsed; a garbage datagram is dropped+counted and monitoring survives; nil sink refused; Serve returns nil on clean shutdown.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D128.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| malformed datagram delivered not dropped | the drop-count assertion fails |
| nil-sink guard removed | Listen accepts a nil sink |
