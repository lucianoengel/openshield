# execaudit-connector (delta)

## ADDED Requirements

### Requirement: The EXECVE parser bounds the argument count
The execaudit EXECVE parser MUST bound the number of argument entries it reads from a record, so a
crafted argument count in attacker-influenced audit text cannot turn parsing into a CPU
denial-of-service. A record whose argument count exceeds the bound MUST parse promptly with the count
capped rather than looping over the claimed count.

#### Scenario: A crafted argument count does not hang the parser
- **WHEN** the parser reads an EXECVE record whose argc is enormous
- **THEN** it returns promptly with the argument count capped at the bound
