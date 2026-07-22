# Tasks — HIPS-5a enforce target by kind
- [x] enforceTarget(ev): pid for process events, resolved path for file events.
- [x] enforce() uses enforceTarget (pid-based enforcer no longer self-refuses).
- [x] registerEnforcers adds KillEnforcer under OPENSHIELD_ENFORCE; DENY_EXEC deferred (comment).
- [x] Real-adversary test: a KILL decision kills a real spawned process; self-target refused + audited.
- [x] Mutation: enforceTarget → filesystem path → the real process survives (test fails).
- [x] make all clean; docs D150; sync; archive; commit; push; memory.
