# agent-process-boundary

## ADDED Requirements

### Requirement: Every decoder in the privileged process MUST survive arbitrary input

Every function decoding bytes the privileged agent did not produce MUST be covered by a fuzz target,
and MUST NOT panic, allocate beyond its declared bounds, or fail to terminate on any input. This
covers kernel event structures and IPC frames alike.

The severity here comes from what the process does rather than from what the language permits. Go rules
out the memory-corruption class outright; what remains is a crash, an out-of-memory, or a spin. In a
process that answers BLOCKING permission events, each of those stops every open of a watched file until
the watchdog budget fires, with the gate failing open throughout — a host-wide availability event, not a
lost feature.

#### Scenario: A malformed kernel event structure is rejected without panicking

- **WHEN** the privileged agent's fanotify metadata decoder is given arbitrary bytes
- **THEN** it MUST return a decode failure rather than panicking

#### Scenario: A malformed IPC frame is rejected without panicking

- **WHEN** an IPC frame decoder reachable from the privileged agent is given arbitrary bytes
- **THEN** it MUST return an error rather than panicking
- **AND** MUST NOT allocate beyond the length its protocol declares

### Requirement: A streaming decoder MUST make progress

A decoder that returns a remainder for its caller to continue from MUST return a remainder strictly
shorter than its input when it reports success, and MUST report failure otherwise.

A decoder that returns its input unchanged is an infinite loop in the process holding CAP_SYS_ADMIN.
Absence of a panic does not cover this: the loop never crashes, it simply stops answering, which
presents as a wedged host rather than as a failure anyone can attribute.

#### Scenario: A successful decode consumes input

- **WHEN** a streaming decoder in the privileged agent reports a successful decode
- **THEN** the remainder it returns MUST be strictly shorter than the buffer it was given

### Requirement: A discovered crashing input MUST become a permanent regression seed

An input that causes a fuzz target to fail MUST be committed to that target's seed corpus.

A fuzzing run is bounded and probabilistic; a seed corpus is neither. Committing the input converts a
one-off discovery into a check that runs on every ordinary test invocation, for as long as the code
exists, at no cost.

#### Scenario: The corpus is replayed without fuzzing

- **WHEN** the test suite runs without any fuzzing flag
- **THEN** every committed corpus entry MUST be executed against its target
