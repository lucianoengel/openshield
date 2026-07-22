## 1. Trusted-identity seam

- [x] 1.1 Add `procIdentity{ExePath string; RootOwned bool; OtherWritable bool}`; change the enforcer's
      injectable `nameOf func(pid)(string,error)` to `identify func(pid)(procIdentity,error)`.
- [x] 1.2 Rewrite `isCriticalProcess` to take a `procIdentity`: critical iff
      `RootOwned && !OtherWritable && (basename(ExePath) ∈ criticalNames || hasPrefix(basename,"openshield"))`.
      Keep `criticalNames` (they are now matched against the real exe basename, not comm).

## 2. Real identity source

- [x] 2.1 `kill_linux.go`: implement `procIdentityOf(pid)` — `readlink(/proc/<pid>/exe)` for ExePath,
      `stat` for RootOwned (uid 0) and OtherWritable (mode & 022 != 0). Replace `procComm` as the default.
- [x] 2.2 `kill_darwin.go`/`kill_other.go`: `procIdentityOf` returns an unsupported error (mirror the
      old `procComm` stubs). Update `NewKillEnforcer` to default `identify: procIdentityOf`.
- [x] 2.3 `EnforceTarget`: call `k.identify(pid)`; refuse when `err == nil && isCriticalProcess(id)`,
      with an audit-visible reason naming the exe basename.

## 3. Verify + mutation guards

- [x] 3.1 Test (injected identify, no root needed): a self-renamed non-root process (basename `sshd`,
      `RootOwned:false`) is TERMINATED; a root-owned critical binary (basename `sshd`, `RootOwned:true,
      OtherWritable:false`) is SPARED; a root-owned but other-writable `sshd` is TERMINATED (not trusted);
      a fleet binary (`openshield-worker`, root-owned) is SPARED.
- [x] 3.2 Test: pid≤1 and self-pid still refused (unchanged guards intact).
- [x] 3.3 Where feasible, an integration check that the real `procIdentityOf` reads this test binary's
      own exe path (sanity that readlink works), without asserting ownership (CI is non-root).
- [x] 3.4 Mutation guards (apply, FAIL, revert): (A) key the critical check on the self-settable name /
      drop the RootOwned requirement → the self-rename test's "terminated" assertion FAILs (it would be
      spared); (B) drop the `!OtherWritable` check → the world-writable-sshd test FAILs. (Confirmed 2026-07-22: (A) drop RootOwned/OtherWritable gate → pid 20 /tmp/evil/sshd spared → FAIL; (B) drop !OtherWritable → pid 21 /opt/sshd world-writable spared → FAIL; both reverted.)

## 4. Gate + record

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...` clean.
- [x] 4.2 decisions.md entry (next D-number).
- [x] 4.3 Roadmap + memory updated.
