## 1. Signed-index envelope (internal/classify)

- [x] 1.1 Add `SignedIndex { string kind = 1; bytes index = 2; bytes signature = 3; }` proto; `make proto`.
- [x] 1.2 `SignIndex(kind string, index []byte, priv ed25519.PrivateKey) ([]byte, error)` — domain-separated signature over (kind, index).
- [x] 1.3 `VerifyIndex(signed []byte, trustedPub ed25519.PublicKey, wantKind string) ([]byte, error)` — fail-closed, verify BEFORE returning bytes, bind kind.
- [x] 1.4 Export kind constants (`IndexKindEDM/Record/IDM`).

## 2. Worker verification (cmd/openshield-worker)

- [x] 2.1 Read `OPENSHIELD_DLP_INDEX_PUBKEY`; when set, each index file must `VerifyIndex` (matching kind) before `Load*` — abort on failure (fail-closed).
- [x] 2.2 When unset, keep legacy unsigned load but log a prominent ADR-9 warning.
- [x] 2.3 Factor the per-index read/verify/load into one helper to avoid three copies.

## 3. Operator tool (cmd/openshield-dlp-index)

- [x] 3.1 `build --type edm|record|idm --in <file> --key <file> --out <file>` (+ type knobs: edm target-fp; record delimiter+threshold; idm k+fraction).
- [x] 3.2 Reuse the shared operator ed25519 key loader; reject malformed input (no partial index).
- [x] 3.3 Build via existing constructors → `Marshal()` → `SignIndex` → write.

## 4. Tests (real path; mutation-verified)

- [x] 4.1 Envelope: sign→verify round-trip (all three kinds); tampered payload, tampered signature, wrong key, wrong kind each FAIL.
- [x] 4.2 Domain separation: a signed rules bundle is not accepted by `VerifyIndex` and vice versa.
- [x] 4.3 Worker helper: under a configured key a signed index loads and detects a seeded value; an unsigned/tampered file aborts.
- [x] 4.4 Tool→worker round-trip: the tool's signed output verifies + loads + detects the operator's seeded value.
- [x] 4.5 Mutations: `VerifyIndex` skips the signature check → tamper test FAILs; skips the kind bind → kind-mismatch test FAILs; worker loads without verifying under a set key → the unsigned-abort test FAILs.

## 5. Gate + close

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`; restore any tracked binaries.
- [x] 5.2 `decisions.md` entry; sync delta spec into `openspec/specs/`; `go test ./internal/doccheck/`.
- [x] 5.3 Archive; commit with trailers; `git pull --rebase` + push; update memory + roadmap status.
