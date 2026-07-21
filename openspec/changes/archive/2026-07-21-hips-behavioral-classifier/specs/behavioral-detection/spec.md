# behavioral-detection delta

## ADDED Requirements

### Requirement: The behavioral analyzer scores process executions for LOLBin, lineage, and encoded-command abuse
The behavioral analyzer MUST score a process execution from its executable, parent, and
arguments — flagging a living-off-the-land binary, a suspicious parent→child lineage (an
office application or a network server spawning a shell/interpreter), and an encoded or
download-and-execute command line — combining the signals into a score with recorded
reasons, over execution metadata only. A routine execution MUST score zero. The analyzer
MUST resolve a binary name from both Windows and Unix paths.

#### Scenario: Malicious execution shape is flagged and routine execution is not
- **WHEN** the analyzer scores a process execution
- **THEN** an office application spawning an encoded interpreter scores high with recorded reasons, while a routine command scores zero
