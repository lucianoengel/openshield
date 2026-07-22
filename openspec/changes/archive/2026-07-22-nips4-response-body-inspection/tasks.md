# Tasks

## 1. Proxy response inspection
- [x] 1.1 `Proxy.inspectResponses bool` + `SetInspectResponses(bool)`.
- [x] 1.2 `readBoundedKeep(r, max) (prefix []byte, tooLarge bool, err error)` — like `readBounded` but
  returns the read prefix even when over-cap, so an over-cap response can be forwarded.
- [x] 1.3 In `forward`: when `inspectResponses`, after RoundTrip read the response body with
  `readBoundedKeep`; on over-cap forward `io.MultiReader(prefix, resp.Body)` UNINSPECTED and record the
  gap; on a read error fail open (forward what remains). Within the cap: gzip-decode the buffered body
  for classification (bounded), `gw.Process` an INGRESS response `Request` (audits the decision), then
  write the ORIGINAL buffered bytes to the client. Inspection off → the current `io.Copy` path unchanged.

## 2. Gateway wiring
- [x] 2.1 `cmd/openshield-gateway`: `proxy.SetInspectResponses(true)` when `OPENSHIELD_INSPECT_RESPONSES`
  is set (default off — buffering every response is opt-in).

## 3. Tests (real sockets, httptest upstream, fake ledger)
- [x] 3.1 Inspection ON: an upstream returns a body with a CPF → the response is classified (a ledger
  entry records the response decision) AND the client receives the exact upstream body.
- [x] 3.2 gzip: the upstream returns a gzip-encoded body with a CPF (Content-Encoding: gzip) → it is
  decoded and classified (a ledger entry), and the client receives the original gzip bytes.
- [x] 3.3 Over-cap: a response larger than the cap is delivered INTACT (byte-for-byte) and recorded as an
  uninspected gap, not refused.
- [x] 3.4 Inspection OFF: the same sensitive response is streamed through with NO response ledger entry
  (unchanged behavior).

## 4. Mutation guards
- [x] 4.1 Make `forward` classify the ORIGINAL (gzipped) bytes instead of the decoded text → the gzip
  test (3.2) FAILs (the CPF inside the compressed body is not found). Revert.
- [x] 4.2 Make the over-cap path truncate to the prefix (drop the remainder) → the over-cap intact test
  (3.3) FAILs (the client gets a short body). Revert.

## 5. Record + close
- [x] 5.1 `docs/decisions.md`: new entry (D200) — NIPS-4 response-body inspection; opt-in; gzip decode +
  original forwarded; over-cap uninspected/fail-open; observe-only (response blocking + multipart +
  streaming are follow-ups).
- [x] 5.2 `docs/architecture-roadmap.md`: note NIPS-4 response inspection shipped.
- [x] 5.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/network-gateway/spec.md`.
