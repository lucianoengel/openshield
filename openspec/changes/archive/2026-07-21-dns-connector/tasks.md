# Tasks — DNS connector (D101)

## 1. Connector

- [x] 1.1 EVENT_KIND_DNS_QUERY; regenerate.
- [x] 1.2 `internal/connectors/dns`: ParseQuery (bounded question decoder, rejects malformed/response/pointer), ToEvent (NetworkSubject, name in sni_host, udp/53), TunnelScore (length×entropy).

## 2. Proof (real DNS bytes; guards mutation-tested)

- [x] 2.1 **Test**: a real query parses to name+qtype and produces a DNS_QUERY event; too-short/no-question/response/truncated/pointer messages rejected (incl. a pointer with room so only the pointer check catches it); ordinary names score low, an exfil label high.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D101.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| label-runs-past-message bound removed | a truncated-name message then over-reads/mis-parses |
| pointer-in-qname check removed | a pointer-with-room message then parses to a garbage name |
| QR response-rejection removed | a response message is then accepted as a query |
| TunnelScore product→sum | a normal name then scores high enough to flag |
