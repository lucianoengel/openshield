# Tasks — syslog UDP listener (D108)

## 1. Listener

- [x] 1.1 `syslog.Listener` (Listen/Serve/Addr/Dropped): UDP bind, parse each datagram to a sink, drop+count malformed, atomic drop counter, clean ctx-cancel shutdown, nil-sink refused.

## 2. Proof (real UDP socket; guards mutation-tested; race-clean)

- [x] 2.1 **Test**: two valid datagrams arrive parsed; a garbage datagram is dropped+counted and ingest survives; nil sink refused; Serve returns nil on clean shutdown.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D108.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| malformed datagram delivered instead of dropped | the drop-count assertion fails (garbage delivered, dropped stays 0) |
| nil-sink guard removed | Listen then accepts a nil sink |
