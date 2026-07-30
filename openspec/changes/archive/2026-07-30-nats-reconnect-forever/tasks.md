# Tasks

- [x] `natsx.ResilienceOptions` — infinite reconnect, jitter, and disconnect/reconnect logging.
- [x] Deliberately omit a `ClosedHandler`, with the reason recorded (fires on clean shutdown).
- [x] Wire into the fleet agent, engine, gateway, and `controlplane.Run` — NOT `controlplane.Connect`.
- [x] `TestAnOutageLongerThanTheReconnectBudgetStillRecovers`.
- [x] Size the outage past the JITTERED budget — the 135s first version could not fail.
- [x] Mutation-verify both directions.
- [x] Confirm the transport, control-plane and fleet scenarios still pass.
- [x] Make the restore drill skip when the container runtime cannot start a container at all, and make the
  CI podman probe functional rather than `--version`.
- [x] `docs/unwired-audit.md` — Round 48.
- [x] `make quick` green.
