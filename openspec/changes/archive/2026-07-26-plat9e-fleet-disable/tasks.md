## 1. Message and consumer
- [x] 1.1 Proto: `FleetVerb` (closed, two verbs) + `FleetControl` with version, sequence and mandatory
      expiry; a dedicated NATS subject.
- [x] 1.2 `intent.FleetControlSubscriber`: verify signature → version → verb → expiry → monotonic
      sequence → apply to an `Applier` (the kill switch). Counts applied and rejected.

## 2. Publisher
- [x] 2.1 `PublishFleetControl` with a deterministic control id, a stored monotonic sequence, mandatory
      signing, and four-eyes on every disable checked BEFORE signing.

## 3. Wiring
- [x] 3.1 `Engine.SubscribeFleetControl`, refusing to subscribe with no kill switch installed.

## 4. Tests
- [x] 4.1 A signed disable stops enforcement; a signed restore resumes it.
- [x] 4.2 A REPLAYED disable is refused (**mutation:** drop the sequence check → FAILS).
- [x] 4.3 Forged signature / unknown version / expired / no expiry / no key — each refused, each leaving
      enforcement ON (**mutations:** ignore expiry, accept any version → FAIL).
- [x] 4.4 An unapproved disable is never published (**mutation:** skip the four-eyes check → FAILS).

## 5. Gate and land
- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 5.2 Record D269; roadmap PLAT-9 residual closed.
- [x] 5.3 Sync specs and archive.
