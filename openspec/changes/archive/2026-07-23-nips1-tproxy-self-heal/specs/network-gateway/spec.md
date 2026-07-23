## ADDED Requirements

### Requirement: The transparent inline plane self-heals after an unexpected stop

The system SHALL re-arm the transparent inline server when it stops for any reason other than a shutdown (a
listener or accept failure) — recreating the listener, reinstalling the self-owned redirect rules, and
resuming enforcement after a backoff — and SHALL keep retrying until its context is cancelled, so a
transient failure does not silently leave the inline network prevention disabled for the rest of the
process's life. A listener that cannot be created MUST be retried the same way rather than abandoning the
plane. On context cancel the loop MUST exit and MUST NOT re-arm.

#### Scenario: The plane re-arms after the listener dies
- **WHEN** the inline server stops unexpectedly while the process keeps running
- **THEN** the plane is re-armed after a backoff and resumes enforcing forwarded flows

#### Scenario: Shutdown stops the supervision loop
- **WHEN** the context is cancelled
- **THEN** the supervision loop exits and does not re-arm
