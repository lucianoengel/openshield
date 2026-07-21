# peer-ueba delta

## ADDED Requirements

### Requirement: The peer baseline excludes the subject under test
Peer-relative risk MUST compute the peer baseline from the OTHER subjects' activity, excluding the
subject being scored, so a subject cannot contaminate the baseline it is judged against.

Under leave-one-out an outlier scores MORE clearly anomalous than when its own activity is folded into
the mean/stddev. A population too small to have peers after excluding the subject still returns no
Context (no risk emitted on noise), preserving the small-population guard.

#### Scenario: An outlier scores higher with leave-one-out than self-included
- **WHEN** a subject far above its peers is scored with the peer baseline excluding it
- **THEN** its risk is at least as high as, and for a strong outlier strictly higher than, a baseline
  that includes its own activity
- **AND** a test asserts the leave-one-out score exceeds the self-included score for a strong outlier

### Requirement: Old activity decays so a steady subject does not drift into anomaly
Accumulated activity MUST decay over time, so a subject with a steady rate of activity reaches a
bounded level near its peers rather than climbing monotonically into a false anomaly.

Decay is deterministic given the time source (an injected clock, not wall-clock inside the analyzer),
so the behavior is testable. A genuine burst still rises above the decayed peer level; only steady
accumulation is bounded.

#### Scenario: A steady-but-busy subject stays within its peers over time
- **WHEN** a subject sustains a steady activity rate comparable to a busy peer over a long period
- **THEN** its decayed level stays bounded near its peers and it is not flagged as an outlier
- **AND** a test shows the same subject WOULD drift into outlier under a non-decaying cumulative count

#### Scenario: The public Analyzer API is unchanged
- **WHEN** the hardened analyzer is used through Observe / ContextFor / Resolver
- **THEN** the signatures and the emitted context_version (D53) are unchanged and downstream wiring
  (the dispatcher hook, the fleet consumer) still compiles and runs
- **AND** the existing peer-UEBA tests continue to pass
