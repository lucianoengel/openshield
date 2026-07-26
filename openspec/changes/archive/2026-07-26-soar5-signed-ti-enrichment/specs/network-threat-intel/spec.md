## ADDED Requirements

### Requirement: An IOC feed may be signed, and verification precedes parsing

The feed loader SHALL support a detached ed25519 signature over the feed's exact bytes. When a
verification key is supplied, the signature SHALL be checked **before** any byte of the feed is parsed,
and a failed check SHALL reject the entire feed. The parser is the untrusted-input surface: verifying
after parsing would mean a hostile feed had already been through it, and rejecting per-line would apply
the attacker-chosen subset that verified.

#### Scenario: An unsigned load path stays available
- **WHEN** no verification key is supplied
- **THEN** the feed loads as before, and the deployment's lack of feed authentication is a configuration
  choice rather than a silent default

#### Scenario: A bad signature rejects the feed before parsing
- **WHEN** a verification key is supplied and the signature does not check out
- **THEN** the load fails, no feed is returned, and the content is not parsed

### Requirement: A feed's format is named, never sniffed

The loader SHALL accept the native line format and a CSV format, selected by an explicit format name.
Detecting the format from the content would let a crafted file choose the parser it is handled by.

#### Scenario: An explicit format is honoured
- **WHEN** a feed is loaded with a named format
- **THEN** it is parsed by that format's parser, and content that is invalid for it is an error

### Requirement: A parsed feed's indicators are enumerable and reconstructable

A feed SHALL expose the indicators it holds, and SHALL be constructible from a list of indicators, so a
consumer can persist a feed and later rebuild the identical matcher. This is what keeps matching to one
implementation instead of one per consumer.

#### Scenario: A feed round-trips through its indicator list
- **WHEN** a feed's indicators are enumerated and used to build a new feed
- **THEN** the rebuilt feed matches exactly the same observables as the original
