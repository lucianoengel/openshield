## 1. The connector

- [x] 1.1 `internal/runner/idp.go`: closed `Action` vocabulary (`disable-user`, `revoke-sessions`),
      `Connector{Name, Endpoint, Token, Actions map[corev1.IntentVerb][]Action, Client, Timeout}`,
      `ActionsFor(verb)` returning nothing for an undeclared verb.
- [x] 1.2 `Connector.Call(ctx, action, subject, intentID)` — one authenticated JSON POST, bounded timeout,
      returning the target and HTTP status for the record.
- [x] 1.3 Tests: the action vocabulary is exactly the two names; an undeclared verb yields no actions; the
      call carries the intent id and subject and the configured token.

## 2. Execution with its controls

- [x] 2.1 Migration `034_runner_actions.sql`: (connector, intent_id) unique, verb, subject, action, target,
      state (claimed|executed|failed), http_status, error, at. Add to every test drop list.
- [x] 2.2 `controlplane.EnactIntent(ctx, conn, intent)`: verb declared → intent not expired → **approval
      for the intent id is approved** → claim → call → record outcome.
- [x] 2.3 Tests (real Postgres, an httptest IdP counting requests):
      - an UNAPPROVED intent makes NO call (**mutation:** skip the approval check → FAILS);
      - an approval for a DIFFERENT intent id does not authorize (**mutation:** look up by subject → FAILS);
      - an approved intent calls and the record links intent id → target + status (**mutation:** record
        without the target → FAILS);
      - redelivery calls exactly ONCE (**mutation:** drop ON CONFLICT → two calls → FAILS);
      - an undeclared verb makes no call and records nothing;
      - an EXPIRED intent makes no call even when approved;
      - a failed call is recorded as `failed` with its cause, and the claim row remains.

## 3. Wiring and honesty

- [x] 3.1 Configure from env; the startup log states plainly that these actions are NOT undone by intent
      expiry.
- [x] 3.2 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 3.3 Record D260; update the roadmap (SOAR-8 → increment 1 of 2 done, ITSM remaining).
- [x] 3.4 Sync specs and archive.
