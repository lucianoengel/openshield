## 1. Severity on notifications

- [x] 1.1 `notify.Notification.Severity` + `SeverityRank(string) (int, bool)` over the closed vocabulary.
- [x] 1.2 `controlplane.emit` stamps `Severity` from the existing `Severity(risk)` mapping when unset, so
      the risk→bucket mapping keeps exactly one home.
- [x] 1.3 Test: each `controlplane.Severity*` constant ranks in `notify`, so the two vocabularies cannot
      drift apart silently.

## 2. The routing table

- [x] 2.1 `internal/notify/route.go`: `Route{Kinds, MinSeverity, Sinks}`, `Router{Sinks map[string]Notifier,
      Routes []Route}` implementing `Notifier` with FIRST-MATCH-WINS.
- [x] 2.2 Unmatched → every sink, `Router.Unrouted` counted; expose
      `openshield_notify_unrouted_total` on `/metrics`.
- [x] 2.3 `LoadRoutes(io.Reader, sinkNames)` validating unknown severity, unknown kind, empty sink list,
      and a sink name that is not configured.
- [x] 2.4 Tests: critical→pager only and low→chat only, proven with two sinks (**mutation:** union of all
      matching rules instead of first-match → critical also reaches chat → FAILS); an unmatched
      notification reaches both sinks and increments the counter (**mutation:** drop unmatched instead →
      FAILS); one failing sink does not suppress the other; every load-validation case is refused;
      a Route struct exposes no subject/entity selector.

## 3. Notify on a pending approval

- [x] 3.1 `notify.KindApprovalPending`; `RequestApproval` emits it carrying the approval id and subject,
      best-effort (the row is the record).
- [x] 3.2 Tests: opening a request emits exactly one notification naming the approval and subject
      (**mutation:** do not emit → FAILS); the request is still recorded when delivery fails; the reason
      text is not used as a routing field.

## 4. Wiring

- [x] 4.1 `OPENSHIELD_ALERT_WEBHOOK` accepts `name=url`; bare URLs keep working, auto-named.
- [x] 4.2 `OPENSHIELD_ALERT_ROUTES` (file) installs the Router; unset keeps today's `Multi` exactly.

## 5. Gate and land

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 5.2 Record D259; update the roadmap (SOAR-9 → DONE, SOAR-2/3 residuals now closed, SOAR maturity).
- [x] 5.3 Sync delta specs and archive.
