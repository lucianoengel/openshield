# Tasks

## 1. CEF parser
- [x] 1.1 `internal/connectors/cef/cef.go`: `Message{Version, Vendor, Product, DeviceVersion, SignatureID,
  Name, Severity string; Extensions map[string]string}`; `maxLine` bound; `Parse(line []byte) (Message,
  error)` — require `CEF:` prefix, split the 7 headers on UNESCAPED pipes (honoring `\|`, `\\`), unescape
  each; parse the extension by locating ` key=` boundaries so a value keeps its spaces, unescape values
  (`\=`, `\\`, `\n`, `\r`). Reject empty / no-prefix / <7-headers / oversized.

## 2. Tests
- [x] 2.1 A canonical CEF line → the 7 headers + extension map; a value with spaces (`msg=worm stopped`)
  is kept whole; multiple extension keys parse.
- [x] 2.2 Escapes: `\|` in a header → a literal pipe in that field; `\=`, `\\`, `\n` in a value →
  literal `=`, `\`, newline.
- [x] 2.3 Rejections: empty line; no `CEF:` prefix; only 5 header fields; a line over `maxLine`.
- [x] 2.4 Round-trip robustness: a real-world-ish line (`CEF:0|Security|threatmanager|1.0|100|worm
  stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 msg=a b c`) parses with src/dst/spt/msg correct.

## 3. Mutation guards
- [x] 3.1 Make the header split a naive `strings.Split` on `|` (ignore `\|`) → the escaped-pipe test
  (2.2) FAILs (a header with `\|` splits into extra fields). Revert.
- [x] 3.2 Make the extension split on plain spaces (ignore key boundaries) → the spaces-in-value test
  (2.1) FAILs (a multi-word value is truncated). Revert.

## 4. Record + close
- [x] 4.1 `docs/decisions.md`: new entry (D202) — SIEM-4 CEF parser; pure untrusted-bytes surface;
  header/extension escaping; malformed rejected; listener+search-path + WEF/cloud-JSON are follow-ons.
- [x] 4.2 `docs/architecture-roadmap.md`: note SIEM-4 CEF parser shipped.
- [x] 4.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/cef-ingest/spec.md`.
