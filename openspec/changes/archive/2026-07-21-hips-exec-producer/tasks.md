# Tasks — HIPS exec producer (D112)

## 1. Producer

- [x] 1.1 `internal/connectors/execaudit`: ParseSyscall (pid/ppid/exe/id, whole-token fields), ParseExecve (argv), ToEvent (combine matched pair → PROCESS_EXEC ProcessSubject Event; refuse mismatch/no-exe/no-id).

## 2. Proof (real auditd records; guards mutation-tested)

- [x] 2.1 **Test**: a powershell -enc SYSCALL+EXECVE pair → ProcessSubject Event, fed to the behavioral analyzer which flags it (full producer→detector path); pid not shadowed by ppid; no-exe/no-id/mismatched-pair rejected.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D112.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| whole-token field guard removed | pid then reads the ppid value (shadowing) |
| audit-id mismatch guard removed | two unrelated records then stitch into one event |
| no-exe guard removed | a SYSCALL with no executable then parses |
