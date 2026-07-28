## ADDED Requirements

### Requirement: A socket path is validated against the platform's address limit

Configuration validation SHALL reject a unix socket path longer than the running platform's
`sockaddr_un` address limit, and the refusal SHALL name the field, the length and the limit.

A socket path SHALL otherwise be validated as a path the product creates: its parent directory must
exist, and the socket itself need not — one side creates it and the other connects to it, so requiring
it to pre-exist would make the creating side unbootable and the connecting side fail closed.

The limit SHALL be the RUNNING platform's, not the smallest across platforms. Rejecting a path that the
host would bind successfully is refusing valid configuration, which is a worse fault than a message that
differs between platforms.

Without this the kernel reports an over-long address as `EINVAL` — "invalid argument" — which names
neither the length nor the cause, and the operator sees a feature that validated cleanly, announced
itself as active, and then did not work.

#### Scenario: An over-long socket path is refused with its length

- **WHEN** a socket setting is given a path longer than the platform's unix address limit
- **THEN** validation fails for that field, and the error states the path's length and the limit

#### Scenario: A socket path within the limit is accepted

- **WHEN** a socket setting is given a path within the limit whose parent directory exists
- **THEN** validation succeeds, whether or not the socket itself exists yet

#### Scenario: A socket path whose parent is missing is refused

- **WHEN** a socket setting names a path whose parent directory does not exist
- **THEN** validation fails for that field, naming the missing directory

#### Scenario: Every socket setting is declared as a socket path

- **WHEN** the declared configuration fields are inspected
- **THEN** every setting naming a socket is declared with the socket-path kind, so the length bound
  applies to all of them rather than to whichever were remembered
