## 1. The CASB engine (`internal/casb`)

- [x] 1.1 Types: `Service{Name, Category string, Sanctioned bool, hostSuffixes []string}`, `Match{Service, Category string, Sanctioned, Upload bool}`, `Catalog{services []Service}`.
- [x] 1.2 `(*Catalog) Classify(host, path, method string) *Match`: match `host` against service host-suffixes (component-aware suffix, mirroring `nips.matchDomain`: `s3.amazonaws.com` matches suffix `amazonaws.com`, `notamazonaws.com` does not); first match wins; `Upload = isMutating(method)` (POST/PUT/PATCH). `path` accepted but unused in inc 1 (documented). Nil/empty catalog → nil.
- [x] 1.3 `Empty()`/`Size()`; a nil catalog is inert.
- [x] 1.4 `LoadCatalog(path)`/`ParseCatalog(io.Reader)`: block grammar (`service <name> category <cat> [sanctioned]`, then `host <suffix>` lines; `#` comments; blank skipped). Malformed = error (unknown directive, `host` outside a service, service with no host, bad/absent category, a degenerately short host suffix — a min-length guard like `nips.minURIIndicator`). Never a silent skip.

## 2. Hot-reload + active catalog

- [x] 2.1 `CatalogWatcher` mirroring `internal/signature/reload.go`: baseline read SYNCHRONOUSLY in the constructor; poll mtime; serve-stale + report on a parse error.
- [x] 2.2 Package-level active catalog: `var active atomic.Pointer[Catalog]`; `SetCatalog(*Catalog)`; package `Classify(host, path, method) *Match` reads the active pointer (nil → nil, inert), like `exfil.Default` but runtime-configured.

## 3. Policy input enrichment

- [x] 3.1 `internal/policy/mapping.go` `buildInput`: in the network-event branch, after setting `event["host"/"method"/"path"]`, add `event["cloud"] = {service, category, sanctioned, upload}` when `casb.Classify(host, path, method)` returns non-nil. Nil → omit the key (pipelines unaffected).

## 4. Wiring

- [x] 4.1 Gateway/engine startup (`cmd/openshield-gateway` and/or the engine cmd that builds the network pipeline): read `OPENSHIELD_CASB_CATALOG` → `casb.LoadCatalog` → `casb.SetCatalog` + start `CatalogWatcher`; loud warn when unset (feature off), like the IOC-feed/NIPS-rules warns. A malformed catalog at startup aborts (fail-closed on config, like the EDM index).

## 5. Tests (real gateway→worker path, no seeded literals — reuse the real-worker harness)

- [x] 5.1 `TestSensitiveUploadToUnsanctionedCloudIsBlocked`: real worker, a CPF body POSTed to an unsanctioned catalogued host, a policy `sensitive AND cloud.upload AND not cloud.sanctioned → BLOCK` → BLOCK.
- [x] 5.2 `TestSensitiveUploadToSanctionedCloudIsAllowed`: the SAME CPF body POSTed to a SANCTIONED host → not BLOCK (allow/alert) — proves the sanctioned flag gates.
- [x] 5.3 `TestCleanUploadToUnsanctionedCloudNotBlocked`: a clean body to the unsanctioned host → the rule needs BOTH, so not blocked.
- [x] 5.4 `TestNonCloudFlowUnaffected`: a POST to a non-cloud host → `event.cloud` absent, rule does not fire.
- [x] 5.5 `TestDownloadFromCloudIsNotUpload`: a GET (CPF body irrelevant) to the unsanctioned host → upload=false → rule does not fire.
- [x] 5.6 `TestCasbCatalogHotReload`: mark the service sanctioned in the catalog at runtime → a previously-blocked upload becomes allowed with no restart (mirror the NIPS reload test).
- [x] 5.7 Engine unit tests (`internal/casb`): Classify host-suffix match/miss, upload-by-method, sanctioned flag, parse errors, watcher reload + serve-stale.

## 6. Mutation verification

- [x] 6.1 Mutation — `casb.Classify` returns nil: `TestSensitiveUploadToUnsanctionedCloudIsBlocked` FAILs (no cloud → rule can't fire). Revert.
- [x] 6.2 Mutation — `Match.Sanctioned` hard-forced false (ignore the flag): `TestSensitiveUploadToSanctionedCloudIsAllowed` FAILs (the sanctioned host now blocks). Revert.
- [x] 6.3 Mutation — `Upload` hard-forced true (ignore method): `TestDownloadFromCloudIsNotUpload` FAILs (the GET now blocks). Revert.
- [x] 6.4 Mutation — watcher reads baseline async / never reloads: `TestCasbCatalogHotReload` (or a unit reload test) FAILs. Revert.

## 7. Gate & land

- [x] 7.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (test in background; `git checkout -- openshield-*` after any build).
- [x] 7.2 decisions.md D-entry; sync the delta into `openspec/specs/exfil-channel-awareness/spec.md` (and refresh its Purpose: CASB now delivered for the network channel); run doccheck (`go test ./internal/doccheck/`).
- [x] 7.3 Update the roadmap: DLP-2 content-aware CASB increment DONE (note as increment 1; file-channel foundation + network cloud-upload now real); archive the change; commit, `git pull --rebase`, push.
