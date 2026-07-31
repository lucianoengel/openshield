# ransomware-canary Specification

## Purpose
Detect a ransomware attack by planting decoy (canary) files and firing a high-severity detection when a
threshold of them are modified or deleted within a short window — the correlated mass-change signature
that separates ransomware (many files encrypted fast) from a lone file edit. A change is confirmed by a
content-hash difference (not a raw filesystem event), high content entropy raises confidence (the
encryption signature), and the detection enters the pipeline as a content-free event for a policy alert.
Automated containment, adaptive thresholds, and per-process attribution are follow-ups.

## Requirements
### Requirement: A ransomware canary fires on correlated mass change of decoys

The system SHALL plant decoy (canary) files in operator-designated directories and record their known-good
baseline, and SHALL fire a ransomware detection when the number of DISTINCT canaries whose content changed
(or that were deleted) within a configured time window reaches a configured threshold. A change to a single
canary MUST NOT fire the detection (a lone anomaly), and changes spread across a period longer than the
window MUST NOT accumulate to a false detection (old changes prune out of the window). A change MUST be
confirmed by a content-hash difference, not a raw filesystem event, so a metadata touch that does not
change content is not counted.

#### Scenario: A burst of canary changes fires
- **WHEN** the threshold number of distinct canaries change within the window
- **THEN** a ransomware detection is fired

#### Scenario: A single canary change does not fire
- **WHEN** only one canary changes
- **THEN** no ransomware detection is fired

#### Scenario: Slow, spread-out changes do not accumulate
- **WHEN** canary changes occur but are spread over a period longer than the window
- **THEN** no ransomware detection is fired (changes older than the window are pruned)

### Requirement: A ransomware detection enters the pipeline as a high-severity event

The system SHALL emit a detected ransomware attack as a distinct high-severity event carrying the affected
location (a directory path) but no file content, so a policy can decide (for example, alert). The event
MUST reach the policy on its metadata — it MUST NOT attempt to open the affected files, which may be
encrypted or deleted. Entropy of a changed canary's content MAY raise the event's confidence (a
high-entropy rewrite is the encryption signature), but a deleted or low-entropy-corrupted canary MUST
still count toward the detection.

#### Scenario: A ransomware detection becomes a policy alert
- **WHEN** the canary detector fires
- **THEN** a content-free ransomware event flows the pipeline to the policy, which can alert, and the outcome is audited without opening the affected files

### Requirement: A ransomware detection names the processes that may be responsible

When the mass-change signal fires, the endpoint SHALL attempt to identify the processes holding
descriptors open under the affected tree, and SHALL emit each as its own PROCESS-targeted event carrying
the pid, the executable path and the process start time.

The detector on its own answers "something is encrypting this tree" — true and unactionable. The next
question is always which process, and until it is answered the only available response is taking the
machine off the network: a containment that routinely costs more than the incident.

The start time SHALL be carried, because with the pid it identifies the process INSTANCE, and a kill
decided now must be able to revalidate at enforcement time rather than landing on a recycled pid.

ATTRIBUTION SHALL BE PRESENTED AS OPPORTUNISTIC. It names SUSPECTS, not culprits: a process that closed
its descriptors between the write and the scan is invisible, and one holding the tree open for a good
reason is present. Documentation SHALL NOT describe it as a substitute for a kernel hook reporting the
writer at write time.

THE DETECTOR SHALL NEVER BE ITS OWN SUSPECT. It reads the canaries to measure their entropy, so it is by
design a process holding canary files open — naming it would send an operator to kill their own agent.

AN ATTRIBUTION THAT COULD NOT LOOK SHALL SAY SO, distinctly from one that found nothing. Reading another
process's descriptor table requires the same user or CAP_SYS_PTRACE, so an unprivileged agent sees only
its own processes and would find nothing every time while reporting a clean result — the reassuring
answer produced by an inability to look. A platform with no process table SHALL likewise report itself
unsupported rather than returning an empty result.

Suspects SHALL be ranked by how much of the tree they hold open and the count SHALL be bounded: a
detection naming forty processes has told an operator nothing they can act on. The ranking SHALL be
stable, because it appears in event ids and in an operator's notes, and a set that reorders between two
scans of the same state reads as the situation having changed.

The process start time SHALL be read from after the comm field rather than by splitting the line, because
a process may put a space or a closing parenthesis in its own name and shift every later field — for
exactly the processes that chose such a name.

#### Scenario: The process holding the canaries open is named
- **WHEN** a mass canary change fires while a process holds those files open
- **THEN** that process is emitted as a suspect with its pid, executable and start time

#### Scenario: The detector does not accuse itself
- **WHEN** the engine holds a canary open to measure its entropy
- **THEN** it never appears among the suspects

#### Scenario: An unrelated process is not accused
- **WHEN** a process holds files open in a different directory
- **THEN** it does not appear as a suspect for the affected tree

#### Scenario: Being unable to look is reported as such
- **WHEN** the scan finds no suspects and was refused access to processes
- **THEN** the result reports itself blind rather than clean

#### Scenario: An awkwardly-named process still yields a usable start time
- **WHEN** a process's own name contains a space or a closing parenthesis
- **THEN** its start time is read correctly rather than shifted
