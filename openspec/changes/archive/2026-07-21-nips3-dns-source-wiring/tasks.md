# Tasks — NIPS-3 DNS source wiring

- [x] DNS listener sink carries the source IP: `func(srcIP string, q Query)`; Serve passes `addr.IP.String()`.
- [x] Update `listen_test.go` (new sink signature + assert source IP is the loopback client).
- [x] `dnsListener` helper in `cmd/openshield-engine` (mint flow id, thread src IP, produce Event, non-blocking send).
- [x] Wire into `main`: `OPENSHIELD_DNS_LISTEN` binds + serves under `wg`, logged; additive, observe-only.
- [x] Test: a real UDP query → a NetworkSubject Event on the channel with SniHost + SrcIp.
- [x] Mutation: source IP dropped in the sink → SrcIp assertion fails.
- [x] `make all` clean; dns + engine packages green.
- [x] docs/decisions.md D133; sync specs; archive; commit; push; memory.
