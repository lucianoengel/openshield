# Tasks

- [x] `TestAnEndpointSurvivesItsOwnNetworkVanishing` — agent in a container, interface removed, rejoined on
  a different IP, spool must drain.
- [x] Own broker on the bridge network (the stack's is slirp4netns and cannot be connected).
- [x] Enrol on the host and carry only the identity into the container, so no listener is widened.
- [x] `PingInterval`/`MaxPingsOutstanding` so a dead-but-open connection is noticed in ~40s, not ~4 min.
- [x] Stop the disconnect log firing on a clean shutdown (nil error means we closed it).
- [x] Mutation-verify: the default ping interval must fail the scenario.
- [x] Confirm the other fleet/outage scenarios still pass together.
- [x] CI: pin podman to a working OCI runtime, since the runner's crun cannot start containers.
- [x] `docs/unwired-audit.md` — Round 49.
- [x] `make quick` green.
