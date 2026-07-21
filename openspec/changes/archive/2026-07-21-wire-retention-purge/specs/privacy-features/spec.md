# privacy-features delta

## ADDED Requirements

### Requirement: Retention purge is scheduled and runs automatically
The system MUST run the retention purge automatically on a periodic timer, not only expose it as a
library function. The local forward-secure ledger MUST purge by TOMBSTONING (erasing content while
keeping the chain skeleton verifiable), and the purge MUST run in the binaries that own a ledger.
Retention MUST NOT be indefinite.

#### Scenario: The ledger purge runs on a timer
- **WHEN** a binary that owns a local ledger has been running past the retention interval
- **THEN** it has invoked the ledger's retention purge, tombstoning bounded-class entries past their age
