## ADDED Requirements

### Requirement: The replay bound survives a restart

A consumer's highest-applied fleet-control sequence SHALL be persisted, and a restarted consumer SHALL
resume from the persisted value rather than from zero.

A bound held only in memory bounds nothing an attacker who can wait gets around. Every control ever
published on the subject is captured by anyone who can read it, verifies perfectly forever, and
becomes live again at the next reboot — which is a package upgrade, a crash loop, or a power cycle.
The refusal logic can be entirely correct and still refuse nothing.

The bound SHALL be written BEFORE the control is applied, and a control whose bound cannot be
persisted SHALL be refused. Applying first and persisting after leaves a window in which a crash
restores a bound below a control that already ran — the replay this exists to refuse. Persisting first
can instead lose a control to a crash, which leaves the host enforcing and the issuer free to re-issue
at a higher sequence; this channel fails toward enforcing everywhere else and does so here too.

#### Scenario: A control captured before a restart is refused after it
- **WHEN** a genuinely signed, unexpired disable that was already applied is re-sent to a restarted
  consumer
- **THEN** it is refused, enforcement stays on, and the refusal is counted

#### Scenario: A control whose bound cannot be written is not applied
- **WHEN** the replay bound cannot be persisted
- **THEN** the control is refused and enforcement is unchanged, rather than taking effect under a
  bound that a restart would not restore

#### Scenario: The channel still delivers after the bound is persisted
- **WHEN** a newly issued control carries a sequence above the persisted bound
- **THEN** it is applied — a persisted bound must not leave a host that can never be told to stop
  enforcing

### Requirement: The replay bound is proven usable at startup, and a corrupt one stops the process

A consumer SHALL read its replay bound and prove it writable when it starts. A bound that cannot be
READ SHALL prevent the consumer starting; a bound that merely cannot be WRITTEN at a path the operator
did not choose MAY be downgraded to an in-memory bound, and the component SHALL say so.

The two failures look alike and must not be treated alike. Continuing from zero after corruption is
exactly the outcome an attacker holding captured controls wants, and a bound that resets whenever its
file is damaged is a bound that anyone able to damage the file can remove. An unwritable path, by
contrast, is an ordinary deployment — a read-only root, a hardened unit file — where refusing to start
would be worse than the window, provided the window is announced rather than assumed.

Proving writability at startup rather than at first use is the difference between learning about a
read-only directory at boot and learning about it during the incident in which the control was needed.

#### Scenario: A corrupt bound refuses to start
- **WHEN** the persisted bound is unreadable or malformed
- **THEN** the component refuses to start rather than resuming from zero

#### Scenario: An unwritable default path is announced, not silently accepted
- **WHEN** the default bound path cannot be written
- **THEN** the component runs with an in-memory bound and states that a restart reopens the replay
  window

### Requirement: The replay bound is not stored with the telemetry sequence

A consumer SHALL refuse to start when its fleet-control replay bound resolves to the same file as the
telemetry sequence.

Both hold a monotonic integer in the same format and one is an obvious place to put the other. Shared,
the publisher's telemetry high-water — which advances every hundred messages — becomes the replay
bound within seconds of boot, and every legitimate control below it is refused as a replay. The result
is a host that can no longer be told to stop enforcing, reporting a replay refusal that is technically
accurate and points nowhere near the cause.

#### Scenario: Two names for the same file are refused
- **WHEN** the replay bound and the telemetry sequence resolve to the same path, by any spelling
- **THEN** the component refuses to start and names both settings

### Requirement: A gateway reports its degraded state in every mode it serves

A gateway SHALL report suppressed enforcement, dropped enforcement-audit appends and fleet-control
outcomes whatever service mode it is running.

These counters were reported only by the Zero-Trust access mode, which is an alternative to the
ordinary proxy path rather than a stage of it — so a gateway doing the thing gateways mostly do
reported none of them. A suppressed gateway is indistinguishable from a quiet one, and that is the
single most misleading silence this product can produce: the operator believes enforcement is running.

#### Scenario: A proxy-mode gateway reports a refused fleet control
- **WHEN** a gateway serving the ordinary proxy path refuses a fleet control
- **THEN** the refusal appears in its degraded-state reporting
