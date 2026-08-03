## ADDED Requirements

### Requirement: A ledger that was anchored but never written to can be reopened

Opening the ledger for writing SHALL succeed when the key-epoch anchor is stored and no entries exist
yet, continuing from the genesis hash exactly as a fresh database does.

The anchor epoch is persisted when a process first opens the ledger; the first ENTRY is written
whenever a decision is first made, which may be much later or never. Between those two moments the
database holds an epoch and no entries, and that is an ordinary state: install, start, notice a wrong
setting, restart. It is also every host whose enforcement was disabled fleet-wide before it decided
anything.

Refusing to reopen there is permanent and self-inflicted — every subsequent start hits the same
branch, so the process can never write the entry that would let it start, and recovery means deleting
a row by hand from an append-only audit store.

The anchor check SHALL still run first: an empty ledger is a reason to continue from genesis, never a
reason to admit a signer that does not own the stored anchor.

#### Scenario: Reopening after a restart with no entries
- **WHEN** a process opens the ledger, writes nothing, exits, and a new process opens it with the same
  signer
- **THEN** the open succeeds, and the first entry written afterwards is sequence 0 committing to the
  genesis hash

#### Scenario: An empty ledger still refuses a foreign signer
- **WHEN** a signer that does not own the stored anchor opens a ledger holding an anchor and no entries
- **THEN** the open is refused, because two signers on one chain is the fork the anchor check prevents
