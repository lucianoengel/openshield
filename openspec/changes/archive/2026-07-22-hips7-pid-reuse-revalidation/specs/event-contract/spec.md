## ADDED Requirements

### Requirement: A process-exec subject can carry the observed process start-time

A process-exec event's subject MUST be able to carry the observed process's start-time (a monotonic
per-process value such as the kernel start-time in clock ticks), alongside the pid, so that a
consumer can distinguish the specific observed process instance from a later process that reuses the
same pid. The field MUST be optional — an event whose producer could not read the start-time carries
it absent (zero), and a consumer MUST treat absent as "identity unknown" rather than as a match. The
start-time is timing metadata, not process content — no file or memory content crosses the boundary.

#### Scenario: The process subject distinguishes a reused pid
- **WHEN** two process-exec events carry the same pid but different start-times
- **THEN** a consumer can tell they are different process instances by the start-time, and an event whose start-time is absent is treated as an unknown identity, not as matching any instance
