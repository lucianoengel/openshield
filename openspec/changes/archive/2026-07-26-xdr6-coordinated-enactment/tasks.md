## 1. Verify the shipped code satisfies each requirement

- [x] 1.1 Two domains, own policies: the gateway overlays the intent in `gateway.go`'s `ResolveContext`;
  the endpoint via `engine.SetIntentResolver`.
- [x] 1.2 One traceable id with no ledger schema change: both stamp `Context.Version` with the intent id,
  and `core/audit.go` copies `ContextVersion` onto the ledger entry.
- [x] 1.3 Coordination and expiry: `TestOneContainIntentIsEnactedByBothDomainsUnderOneID` (both allow
  before; BLOCK + DENY_EXEC under one id; both allow after expiry) and
  `TestAPolicyThatIgnoresIntentsIsUnaffected`.

## 2. Land the delta

- [x] 2.1 `openspec validate`; sync the `response-intent` delta; archive.
- [x] 2.2 Commit noting this is retroactive documentation of D254.
