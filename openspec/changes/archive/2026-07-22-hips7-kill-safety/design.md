# Design — KILL safety

## Never kill the host or the platform

A HIPS verdict that terminates init, sshd, the database, or the fleet's own agent is a self-inflicted
outage worse than the threat. The enforcer reads the target's kernel `comm` (world-readable, so it
works across privilege) and refuses a critical name. The fleet's own binaries are matched by the
`openshield` prefix, which also survives comm's 15-char truncation (`openshield-engine` → `openshield-engi`).
If the comm can't be read the process is almost certainly already gone (comm is readable for any live
process), and the pid-reuse-safe kill no-ops a dead instance — so an unreadable name does not force a
blind kill.

## PIDFD closes the reuse window

A pid is a number, and a dead process's number is reused. A plain `kill(pid)` between a decision and
its enforcement can hit a different, newer process. `pidfd_open(pid)` returns a handle to the SPECIFIC
instance; `pidfd_send_signal` targets that instance, returning ESRCH if it exited — so a recycled pid
is never signalled. This closes the enforcer-internal check→kill window (the check and the signal
concern the same instance) and the recycled-pid hazard. The full decide→kill window would need the
Event to carry a process identity (it carries only the pid); that residual is narrow and noted.

## Bound the parser

`ParseExecve` reads each `aN` by scanning the whole line, so its cost is O(argc·len). `argc` comes
from attacker-influenced audit text, so an unbounded argc is a CPU denial-of-service — a crafted
`argc=2000000000` would loop billions of times. Capping argc at 1024 (far above any real exec's argv)
makes parsing prompt regardless of the claimed argc.

## Proven

The critical guard is tested with injected comms — systemd/sshd/postgres/`openshield-*` are refused
(the kill is never invoked) while an ordinary process is killed; removing the guard kills systemd
(the test fails). The argc bound is tested with `argc=2e9` returning promptly with ≤1024 args;
removing the cap hangs the parse (the test times out).
