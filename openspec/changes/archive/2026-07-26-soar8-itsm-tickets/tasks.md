## 1. Connector

- [x] 1.1 `internal/runner/itsm.go`: `ITSMConnector{Name, Endpoint, Token, ClosedStatuses, MinSeverity,
      Client, Timeout}`; `CreateTicket` (POST → remote ref + url); `TicketStatus` (GET → status string);
      `MeansClosed(status)` over the CLOSED declared set.
- [x] 1.2 Test: `MeansClosed` is true only for declared statuses, case-insensitively; an unknown status is
      false (**mutation:** treat any non-open status as closed → FAILS).

## 2. Sync

- [x] 2.1 Migration `035_itsm_tickets.sql`: `(connector, incident_id)` unique, ticket_ref, ticket_url,
      last_status, created_at, last_synced_at. Add to every test drop list.
- [x] 2.2 `controlplane.SyncITSM(ctx, conn)`: create tickets for matching un-ticketed incidents; poll open
      tickets and transition to `closed` on a declared closed status, attributed `itsm:<name>`.
- [x] 2.3 `RunITSMLoop` over `retain.Loop`, leader-only, with a failure counter; wire behind
      `OPENSHIELD_ITSM_ENDPOINT`.

## 3. Tests (real Postgres + an httptest ITSM)

- [x] 3.1 A matching incident opens exactly ONE ticket across repeated syncs; a below-floor incident opens
      none.
- [x] 3.2 **Acceptance:** closing the ticket transitions the incident to closed (**mutation:** do not
      transition → FAILS).
- [x] 3.3 An UNKNOWN remote status changes nothing (**mutation:** default-to-closed → FAILS).
- [x] 3.4 A reopened ticket does NOT reopen the incident (forward-only survives).
- [x] 3.5 The transition is attributed to the connector, and the acknowledgement is NOT a person.
- [x] 3.6 The ticket body carries the pseudonymous subject and counts, and no evidence content.

## 4. Gate and land

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 4.2 Record D261; roadmap SOAR-8 → DONE, Lane B complete.
- [x] 4.3 Sync specs and archive.
