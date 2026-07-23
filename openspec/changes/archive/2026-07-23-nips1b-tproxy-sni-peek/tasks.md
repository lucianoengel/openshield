## 1. Defensive SNI extractor (`internal/gateway/sni.go`)

- [x] 1.1 `extractSNI(b []byte) string` — walk the TLS record header (handshake=22), the ClientHello handshake header (type=1), the fixed fields (version, random[32], session-id, cipher-suites, compression) to the extensions, and return the `server_name` (ext 0x0000) host. Every length bounds-checked against `len(b)` before use; no slice sized from an attacker length. Not-a-ClientHello / truncated / no-SNI → `""`, never a panic.

## 2. Peek + decide-on-SNI + replay (`internal/gateway/tproxy.go`)

- [x] 2.1 `DecideFunc` gains a `hint FlowHint{SNI string}` arg; the gateway-backed decider sets `Request.Host = hint.SNI` (the IOC domain match + host policy then apply). The L4 fallback (no SNI) decides exactly as before.
- [x] 2.2 `handleFlow` peeks up to `maxPeek` bytes under a short read deadline into a buffer (reset the deadline after), extracts the SNI, and decides with the hint. On splice, the upstream copy is `io.MultiReader(bytes.NewReader(peeked), client)` so the ClientHello is replayed. A peek timeout/error → empty peek, empty SNI, decide on metadata, splice (fail-open).

## 3. Tests (no root)

- [x] 3.1 `TestExtractSNI`: a real TLS ClientHello (built via `tls.Client` handshake bytes, or a captured constant) → the SNI; a non-TLS buffer → `""`; a truncated ClientHello → `""` (no panic); a ClientHello with no server_name → `""`; a record with an attacker-huge extension length → `""` (no over-read/panic).
- [x] 3.2 `TestHandleFlowBlocksBySNI`: a client that sends a ClientHello for a denied SNI (decider blocks on `hint.SNI`) → the flow is dropped (client closed, origin gets no bytes).
- [x] 3.3 `TestHandleFlowReplaysPeekedBytes`: an allowed flow — the bytes the client sent first (the peeked buffer) reach the origin, followed by later bytes, in order (byte-for-byte transparent).
- [x] 3.4 `TestHandleFlowPeekTimeoutFailsOpen`: a client that sends nothing → the peek times out, the flow decides on metadata (allow) and splices later bytes — not dropped.

## 4. Mutation verification

- [x] 4.1 Mutation — the decider ignores `hint.SNI` (Host left empty): `TestHandleFlowBlocksBySNI` FAILs (the denied SNI is no longer blocked). Revert.
- [x] 4.2 Mutation — `handleFlow` does not replay the peeked bytes (splices only the remainder): `TestHandleFlowReplaysPeekedBytes` FAILs (the origin misses the ClientHello bytes). Revert.
- [x] 4.3 Mutation — `extractSNI` skips a bounds check (uses an attacker length directly): the attacker-huge-length test FAILs (panic/over-read). Revert.

## 5. Gated VM test (extend the TPROXY kernel test)

- [x] 5.1 Extend `tproxy_kernel_test.go` (or add a case): from the netns, an `openssl s_client -servername EVIL` (or a Go `tls.Dial` with a denied ServerName) to an allowed dst IP is DROPPED by SNI; a benign SNI to the same IP is spliced. Run on the VM; paste the result. (If `openssl`/tooling is unavailable, drive a raw ClientHello via the netns bash /dev/tcp helper.)

## 6. Gate & land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (the gated kernel test SKIPS without root); cross-compile clean.
- [x] 6.2 Run the extended gated test on the VM; paste the PASS into the D-entry.
- [x] 6.3 decisions.md D-entry; sync the delta into `openspec/specs/network-gateway/spec.md`; doccheck.
- [x] 6.4 Update the roadmap: NIPS-1 SNI peek (increment 2) DONE — inline plane now blocks by domain; content-signature-over-flow = increment 3. Archive; commit; `git pull --rebase`; push.
