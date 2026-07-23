## 1. Pass the peeked payload to the decision

- [x] 1.1 `internal/gateway/tproxy.go`: `FlowHint` gains `Payload []byte`; `handleFlow` sets it from the peeked buffer (same bytes as the SNI peek — no extra read).
- [x] 1.2 The gateway-backed decider in `NewTProxyServer` sets `Request.Body = hint.Payload`, so the existing `bodyClassifyStage → worker → content-signature → threat → policy` path fires. Fail-open and splice-replay unchanged.

## 2. Tests

- [x] 2.1 `TestTProxyPayloadSignatureBlocks` (real worker, no root): build `openshield-worker` with `OPENSHIELD_NIPS_RULES` (a `content` signature); `NewFromWorker` a gateway with a policy that blocks on a content-signature threat; drive a loopback flow via `NewTProxyServer(gw).decide` + `handleFlow` whose payload contains the pattern → the flow is DROPPED (origin gets no bytes).
- [x] 2.2 `TestTProxyPayloadCleanSplices`: the same setup, a payload matching no signature → the flow is spliced (origin receives it).

## 3. Mutation verification

- [x] 3.1 Mutation — the decider does not set `Request.Body` (payload not classified): `TestTProxyPayloadSignatureBlocks` FAILs (the malicious payload is no longer dropped). Revert.

## 4. Gate & land

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile clean.
- [x] 4.2 decisions.md D-entry; sync the delta into `openspec/specs/network-gateway/spec.md`; doccheck.
- [x] 4.3 Update the roadmap: NIPS-1 payload content-signatures (increment 3) DONE — the full NIPS-2 engine now runs inline (dst-IP + SNI + payload). Archive; commit; `git pull --rebase`; push.
