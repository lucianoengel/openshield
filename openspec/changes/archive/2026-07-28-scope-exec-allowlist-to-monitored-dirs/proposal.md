## Why

**`OPENSHIELD_EXEC_ALLOW` bricks the host it is enabled on, and the machine cannot be recovered without a
reboot.** Demonstrated on the rooted VM: with an allowlist naming one binary in one monitored directory,

```
/home/coder/probe/bin/permitted-tool: Operation not permitted
/usr/bin/sudo:                        Operation not permitted
/usr/bin/cat:                         Operation not permitted
/bin/bash:                            Operation not permitted   ← sshd could not start a login shell
```

The cause is a scope mismatch that is already written down in the code. Exec-permission events are only
delivered for a **mount** mark — a directory inode mark does not deliver `FAN_OPEN_EXEC_PERM` for files
executed inside it — so `execmon.Open` marks the whole mount and says so:

> This is broader than the named path (the whole mount); a later increment can narrow with per-file
> marks or path filtering.

For a **deny-list** that breadth is harmless: only the named binaries are refused, wherever they live.
For an **allow-list** it is catastrophic, because the rule is *everything not named is refused* — and
"everything" turns out to mean every executable on the filesystem, not the ones under
`OPENSHIELD_EXEC_MONITOR_DIRS`.

The failure is unrecoverable in the way that matters: stopping the agent needs `sudo`, `sudo` needs
`exec`, and `exec` is denied. Logging in needs a shell, which is also denied. The only exit is a power
cycle. An operator following the documentation — point `EXEC_MONITOR_DIRS` at a directory, list the
binaries permitted there — loses the machine.

## What Changes

- **The default-deny is scoped to the monitored directories.** An exec whose resolved path is not under
  any `OPENSHIELD_EXEC_MONITOR_DIRS` entry is OUT OF SCOPE and permitted, regardless of the allowlist.
  Within those directories the allowlist behaves exactly as documented.
- **The deny-list is deliberately left unscoped.** The asymmetry is the point: an explicit list of
  binaries to refuse is safe at any breadth, because its blast radius is exactly what it names. An
  implicit refusal of everything-not-named is only safe inside a declared boundary.
- **The startup warning names the real scope**, so an operator can see what the blast radius is rather
  than inferring it from a setting name.

**BREAKING for anyone relying on the current behaviour** — which is nobody, because the current behaviour
is an unrecoverable outage.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `inline-prevention`: application whitelisting gains a defined scope, and the mount-vs-directory
  distinction becomes a stated requirement rather than a code comment.

## Impact

- `internal/agent/execmon` — the evaluator learns its scope; `cmd/openshield-agent` passes the monitored
  directories in.
- No proto change, no migration, no configuration change: `OPENSHIELD_EXEC_MONITOR_DIRS` already carries
  the information, it simply was not reaching the decision.
- **Risk of the fix itself:** narrowing a security control. Mitigated by leaving the deny-list untouched
  and by the fact that the narrowed region is exactly what the operator asked to police — the removed
  behaviour is the part nobody could deploy.
