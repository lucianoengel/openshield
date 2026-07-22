# Tasks — SEC-7 prefilter no-follow read (D120)

## 1. Fix

- [x] 1.1 safeio.OpenRegularNoFollow (unix + other); prefilter openFile uses it.

## 2. Proof (guard mutation-tested)

- [x] 2.1 **Test**: the prefilter refuses a symlinked target; a regular file reads normally.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D120.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| revert to os.Open | the symlink target is then followed (test fails) |
