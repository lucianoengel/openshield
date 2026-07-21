# Tasks — gateway tunnel audit (D78)

## 1. RecordTunnel

- [x] 1.1 `Gateway.RecordTunnel(ctx, host, reason string)` — append a metadata-only `core.Entry{OutcomeKind:"tunneled", OutcomeStage: "<host> (<reason>)", Retention: standard, AppendedAt: now}` (nil Decision). Log an append error; return without failing.

## 2. Proxy wiring

- [x] 2.1 `Proxy.handleConnect`: in the tunnel branch compute the reason ("interception-disabled" when `p.minter == nil`, else "do-not-intercept") and call `p.gw.RecordTunnel(hostOnly(r.Host), reason)` before relaying.

## 3. Proof (guards, each mutation-tested)

- [x] 3.1 **Test**: a blind-tunneled HTTPS request records exactly one "tunneled" entry whose OutcomeStage names the destination host and reason interception-disabled; the entry has no Decision and no body. (Updates the D74 test that asserted zero entries.)
- [x] 3.2 **Test**: a do-not-intercept host records a "tunneled" entry with reason do-not-intercept. (Updates the D75 test that asserted zero entries.)
- [x] 3.3 **Test**: an intercepted flow records its Decision and NO "tunneled" entry (the paths are distinct).
- [x] 3.4 **Test**: the tunnel still works end to end when the ledger append fails (best-effort — a failing fake ledger does not break the tunnel).

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D78: tunneled/uninspected flows are recorded as a metadata-only ledger entry (destination host + reason, no body/path/decision); best-effort, never breaks the tunnel; distinct from an inspected flow's Decision entry.
- [x] 4.2 `openspec validate gateway-tunnel-audit --strict`; `make all` + `-race`; doccheck; archive via the skill; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| tunnel not recorded | `TestProxyTunnelsHTTPSWithoutInspecting`, `TestDoNotInterceptTunnelsExcludedHost` |
| wrong reason (always interception-disabled) | `TestDoNotInterceptTunnelsExcludedHost` |
| tunnel entry carries a Decision (claims inspection) | `TestProxyTunnelsHTTPSWithoutInspecting` (decision != nil) |

THE VERDICT (D78): uninspected tunneled flows (blind tunnel + do-not-intercept) are now recorded as a
metadata-only "tunneled" ledger entry — destination host + reason, no body, no path, no decision — so
uninspected egress is visible in the audit trail; best-effort, never breaks the tunnel; distinct from an
inspected flow's Decision entry. NOT in scope: telemetry projection of tunnel records; per-request
records; inner-ClientHello SNI.
