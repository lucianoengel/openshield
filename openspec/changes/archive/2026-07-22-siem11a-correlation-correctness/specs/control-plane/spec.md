# control-plane (delta)

## MODIFIED Requirements

### Requirement: The control plane correlates alerts into incidents by a burst rule
The control plane MUST correlate peer alerts into incidents by grouping a subject's alerts
within a time window and above a risk floor, raising an incident only when the count reaches
a threshold. An incident MUST carry the subject, the alert count, the peak risk, the time span,
and the number of DISTINCT originating hosts (agents) the alerts came from, counting only real
hosts — a legacy/pre-identity alert with no host MUST NOT count as a distinct host. A subject below
the count threshold, outside the window, or below the risk floor MUST NOT raise an incident. The
correlation MUST accept an optional minimum-distinct-hosts threshold, so that an operator can select
only subjects anomalous across two or more agents — a cross-host incident — while a minimum of one
(the default) preserves the plain burst rule. The correlation MUST be parameterized (operator input
as data), its read surface MUST be operator-gated, and a malformed correlation or overdue parameter
MUST be rejected rather than silently defaulted.

#### Scenario: A burst raises an incident and a quiet subject does not
- **WHEN** the correlation rule runs over the alert aggregate
- **THEN** a subject with enough alerts in the window raises one incident with its count, peak risk, and distinct-host count, while a single-alert or out-of-window subject does not, and a non-operator is refused

#### Scenario: A cross-host threshold selects only multi-agent subjects
- **WHEN** the correlation rule runs with a minimum-distinct-hosts threshold of two
- **THEN** a subject whose qualifying alerts span two or more real agents is raised, while a subject whose alerts all came from a single agent — even with additional legacy hostless alerts — is excluded

#### Scenario: A malformed correlation or overdue parameter is refused
- **WHEN** an operator requests incidents or overdue agents with a malformed window, risk, count, or threshold parameter
- **THEN** the request is refused with 400 rather than silently widened to the default
