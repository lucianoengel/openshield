# Tasks — access-mode binary (D90)

## 1. Catalog parsing

- [x] 1.1 `gateway.ParseCatalog(spec string) (*Catalog, error)` — parse "name=url,name2=url2"; error on a bad entry (no '=') or an unparseable/host-less URL. `Catalog.Len() int`.

## 2. Access-mode binary branch

- [x] 2.1 `cmd/openshield-gateway`: when `OPENSHIELD_ACCESS_MODE` is set, run the access proxy and return (else the existing forward-proxy path). Reuse the worker pool + ledger. Load the policy from `OPENSHIELD_ACCESS_POLICY` (policy.New; abort if missing/unparseable), parse `OPENSHIELD_ACCESS_CATALOG` (abort if empty), build `NewAccessProxy(gw, catalog)` + `SetRiskStore(NewRiskStore())`.
- [x] 2.2 Serve over TLS: `RequireAndVerifyClientCert`, `ClientCAs` from `OPENSHIELD_ACCESS_CLIENT_CA`, server cert/key from `OPENSHIELD_ACCESS_SERVER_CERT`/`_KEY`, on `OPENSHIELD_ACCESS_LISTEN`. Abort on any missing input. Log the posture (client-cert-required, N services) on start.

## 3. Proof (guards, each mutation-tested)

- [x] 3.1 **Test**: `ParseCatalog("payroll=http://payroll.internal:8080,wiki=http://wiki.internal")` → Len 2, both resolve; a no-'=' entry errors; a host-less/unparseable URL errors; an empty spec errors (or Len 0 per the contract — the binary rejects empty).
- [x] 3.2 `go build ./cmd/openshield-gateway` + the deps guard (no internal/classify) stay green.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D90: the ZT access gateway is runnable — access mode serves the AccessProxy over client-cert-required TLS with a file-loaded default-deny policy, an env catalog, and a RiskStore, reusing the worker pool + ledger; fail-fast + loud config; egress OR access; the risk-publish channel A.5b populates the RiskStore.
- [x] 4.2 `openspec validate gateway-access-mode-binary --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| ParseCatalog silently skips a bad entry | `TestParseCatalog` |
| ParseCatalog accepts a host-less URL | `TestParseCatalog` |

THE VERDICT (D90): the ZT access gateway runs as a binary — cmd/openshield-gateway ACCESS MODE serves
the AccessProxy over client-cert-required TLS with a file-loaded default-deny policy, an env catalog, and
a RiskStore, reusing the worker pool + ledger; config is fail-fast + loud (never boots permissive); egress
OR access. ParseCatalog proven; deps guard green. NOT in scope: risk-publish channel (A.5b), bespoke
systemd unit, OIDC (A.2b), posture producer, hot-reload.
