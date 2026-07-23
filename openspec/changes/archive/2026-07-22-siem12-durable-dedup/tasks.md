## 1. Durable dedup store

- [x] 1.1 Migration `023_notify_dedupe.sql` — `notify_dedupe(id TEXT PRIMARY KEY, emitted_at TIMESTAMPTZ NOT NULL DEFAULT now())` + an emitted_at index for pruning.
- [x] 1.2 `Server.markNotifyDurable(ctx, id) (isNew bool, err error)` — INSERT ON CONFLICT DO NOTHING; nil pool → (true, nil); fresh timeout ctx.
- [x] 1.3 `Server.PruneNotifyDedupe(ctx, before) (int64, error)`.

## 2. Wire into emit + retention

- [x] 2.1 `emit`: after the in-memory pre-check, durable check — durable duplicate → suppress+count; DB error → log + proceed (fail-open).
- [x] 2.2 Prune the dedup table on the leader retention loop in cmd/openshield-server.

## 3. Tests (real path; mutation-verified)

- [x] 3.1 Cross-restart: server A (real pool) emits+delivers; a FRESH server B on the SAME pool emits the same alert in the same window → NOT delivered.
- [x] 3.2 Fail-open: a Server whose durable insert errors (closed pool) still delivers the alert.
- [x] 3.3 Prune: an id older than the window is pruned and a later same-id emit delivers again.
- [x] 3.4 Existing in-memory dedup test (pool-less Server) still passes (fail-open path).
- [x] 3.5 Mutations: emit ignores the durable result → the cross-restart test FAILs; markNotifyDurable treats a conflict as new → the cross-restart test FAILs.

## 4. Gate + close

- [x] 4.1 Migration count test 22 → 23; `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; cross-compile; restore binaries.
- [x] 4.2 `decisions.md` entry; sync delta spec into `openspec/specs/`; `go test ./internal/doccheck/`.
- [x] 4.3 Archive; commit with trailers; `git pull --rebase` + push; update roadmap.
