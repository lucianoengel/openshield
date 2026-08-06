# network-gateway

## ADDED Requirements

### Requirement: A refusal is counted before it is answered

Where the access broker both COUNTS a refusal and TELLS the peer about it, the count SHALL be made before
the refusal is written to the connection. This holds for every refusal on the SOCKS path, including the
method-negotiation refusal written before any request is read.

The counters are the only evidence a refusal ever happened — the connection is closed and the client is
gone. Counting after the answer means a peer holding the refusal can read a count that does not yet
include it, so anything that reacts to the refusal and then reads the count — a test, a probe, an operator
watching a dashboard while reproducing the case — sees a number that is wrong for as long as the writing
goroutine is not scheduled. Counting first costs nothing and makes the count sound: the peer cannot have
the answer without the count already being made. The CONNECT tunnel on the same proxy has always counted
first; SOCKS was the deviation.

#### Scenario: A client holding a refusal is holding a counted one
- **WHEN** a client has read the authentication refusal for a ticket issued to another device
- **THEN** the refusal counter already includes it, with no waiting

#### Scenario: The rule holds for the refusals that are not authentication
- **WHEN** a client is refused for asking BIND or UDP ASSOCIATE, or for naming a target the catalogue
  does not carry
- **THEN** in each case the counter already includes the refusal once the client has read the reply
