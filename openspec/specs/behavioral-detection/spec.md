# behavioral-detection Specification

## Purpose
The process-behavior detection domain: a standalone analyzer that scores a process execution from its executable, parent, and arguments — flagging living-off-the-land (LOLBin) abuse, suspicious parent→child lineage, and encoded/download-and-execute command lines — over execution metadata only. It is a different classifier shape than content patterns, producing a Finding a policy acts on; the policy (with the closed action set) decides the verdict.

## Requirements

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
