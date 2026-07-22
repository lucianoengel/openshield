# Tasks — PLAT-4b metrics auth + bind guard
- [x] RequireBearerToken (constant-time) wraps /metrics when OPENSHIELD_METRICS_TOKEN set.
- [x] IsNonLoopbackBind; server warns loudly on a non-loopback bind with no token.
- [x] Tests: token no/wrong/missing-scheme -> 401, exact -> 200; loopback vs exposed addresses.
- [x] Mutation: drop the constant-time compare -> tokenless request admitted.
- [x] make all clean; docs D161; sync; archive; commit; push; memory.
