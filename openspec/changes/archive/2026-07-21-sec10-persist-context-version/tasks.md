# Tasks — SEC-10 persist context-version base (D126)

## 1. Fix

- [x] 1.1 Migration 014 peerueba_version; peerueba.WithStartVersion; Server.reserveVersionBase (block reservation); EnablePeerUEBA seeds the base.

## 2. Proof (guards mutation-tested)

- [x] 2.1 **Test**: (unit) different bases → different versions, same base deterministic; (Postgres) two startups → disjoint versions.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D126.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| don't reserve a base (start at 0) | two restarts then collide |
| WithStartVersion ignores the base | the base no longer disambiguates → collision |
