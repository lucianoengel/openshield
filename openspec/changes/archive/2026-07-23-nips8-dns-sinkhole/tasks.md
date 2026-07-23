## 1. The resolver (`internal/dnssink`)

- [x] 1.1 `nxdomain(query []byte) []byte` — build an NXDOMAIN response from the query: copy the txn id, set QR=1 + RCODE=3 + RA, copy QDCOUNT and the question section, zero AN/NS/AR. Bounds-checked (a too-short query → nil, handled by the caller as fail-open forward).
- [x] 1.2 `Resolver{Upstream string, Blocked func(name string) bool, Timeout time.Duration}` + `Serve(ctx, pc net.PacketConn)`: read datagrams; per datagram in a goroutine: `dns.ParseQuery` — on error FORWARD (fail-open); on success, if `Blocked(name)` write `nxdomain(query)` to the client (do NOT forward); else `forward` to `Upstream` and relay the response to the client. Bounded read buffer (4 KiB); a per-forward timeout.
- [x] 1.2b `forward(query []byte, client addr, pc)` — dial the upstream UDP, write the query, read the response under the timeout, write it back to the client. An upstream error is logged (the query fails as with any resolver — not a sinkhole).

## 2. Wiring (`cmd/openshield-gateway`)

- [x] 2.1 When `OPENSHIELD_DNS_SINK_LISTEN` + `OPENSHIELD_DNS_UPSTREAM` are set, bind the UDP listener and run `dnssink.Resolver{Upstream, Blocked: feed-domain-match}` — the block function reads the CURRENT IOC feed (`gw`'s feed) so a hot-reloaded indicator is sinkholed with no restart. Loud log; a bind failure logs and continues WITHOUT the sinkhole (fail-to-wire, never fail-closed the network), like the TPROXY plane.

## 3. Tests (`internal/dnssink`, no root — high UDP port)

- [x] 3.1 `TestSinkholesBlockedDomain`: a stub upstream that records whether it was queried; a resolver with `Blocked={evil.com}`; send a real A query for `evil.com` → the response is NXDOMAIN (RCODE 3) AND the upstream was NOT queried. A subdomain `c2.evil.com` is also sinkholed.
- [x] 3.2 `TestForwardsNormalQuery`: a query for `good.com` → forwarded to the stub upstream (which answers a canned A record) and the client receives that response.
- [x] 3.3 `TestFailOpenOnUnparseable`: a garbage datagram → forwarded to the upstream (fail-open), not dropped.
- [x] 3.4 `TestNxdomainWellFormed`: `nxdomain(query)` sets QR/RCODE=3, echoes the txn id and question, zero answers; a too-short query → nil.

## 4. Mutation verification

- [x] 4.1 Mutation — `Serve` forwards instead of sinkholing a blocked domain: `TestSinkholesBlockedDomain` FAILs (NXDOMAIN not returned / upstream queried). Revert.
- [x] 4.2 Mutation — `Serve` drops (does not forward) an unparseable/unmatched query: `TestFailOpenOnUnparseable` or `TestForwardsNormalQuery` FAILs. Revert.

## 5. Gate & land

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile clean.
- [x] 5.2 (SKIPPED: the resolver is fully proven on a high port — binding :53 is a trivial OS bind, not novel logic; fail-to-wire covers a bind failure) (Optional) bind a privileged port on the VM and confirm a real `dig`/query is sinkholed; note it.
- [x] 5.3 decisions.md D-entry; author the new capability spec under `openspec/specs/dns-sinkhole/`; doccheck.
- [x] 5.4 Update the roadmap: NIPS-8 DNS sinkhole (increment 1) DONE — DNS is now preventive (sinkhole + forward + fail-open); cache/failover/transparent-redirect are follow-ons. Archive; commit; `git pull --rebase`; push.
