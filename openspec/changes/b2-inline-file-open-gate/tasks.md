# Tasks

- [ ] 1. IPC wire for open-permission questions: `{ID, PID, Path, Prefix}` → `{ID, Verdict}`, with the
      prefix length bounded in the encoder so an over-long frame is a local error.
- [ ] 2. Unit tests for the wire: round-trip, bounded prefix, a truncated frame is an error and never a
      permissive default.
- [ ] 3. `FAN_OPEN_PERM` producer, directory-scoped, refusing a mount-wide scope. Linux-gated with a
      portable stub.
- [ ] 4. The producer reads the bounded prefix from the event's descriptor — never re-opening the path.
- [ ] 5. `cmd/openshield-agent`: wire the producer to the watchdog behind a setting, off by default.
- [ ] 6. `cmd/openshield-engine`: serve open-permission questions from the existing prefilter.
- [ ] 7. Settings, declared (both config registries and the runbook — three guards will insist).
- [ ] 8. VM, in order: ALLOW path first, then DENY, each under `sudo -n timeout N`.
- [ ] 9. Mutation on the VM: the gate always allows → the DENY scenario fails.
- [ ] 10. Budget measurement, as the exec gate has.
- [ ] 11. Targeted tests green; decision record; spec sync on archive.
