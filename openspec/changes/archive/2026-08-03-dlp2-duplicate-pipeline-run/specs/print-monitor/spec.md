## ADDED Requirements

### Requirement: A producer that returns a verdict runs the pipeline exactly once

A producer that obtains a decision it will act on SHALL run the pipeline once for that job, and SHALL
NOT additionally hand the event to the observation path.

Out-of-band content is released when it is resolved, so a second run over the same event obtains
nothing. For a job whose entire content arrives out of band, an empty classification is a CLEAN
result rather than an error — the blind run is indistinguishable from a genuinely clean document, and
when it is the run that produces the verdict, the job is allowed.

Which of two concurrent runs obtains the content is a race, so the requirement is on the count: one
job, one classification, one ledger entry.

#### Scenario: One job produces one classification and one ledger entry
- **GIVEN** the observation path is being drained, as it is in production
- **WHEN** a print job containing detectable content is decided
- **THEN** the classifier runs once, exactly one run carries the document, the ledger records one
  entry, and the verdict refuses the job

#### Scenario: A second run over the same job is blind
- **WHEN** the pipeline is run twice over one job whose content was registered once
- **THEN** the first run detects the content and the second decides as though the job were clean,
  without reaching the classifier or reporting an error

### Requirement: Content requested twice for one event is counted

The out-of-band content store SHALL count a resolution request for an event whose content it has
already released, and that count SHALL be readable outside the store.

A duplicate pipeline run leaves no other trace: the blind run classifies nothing and looks exactly
like a clean result. A plain miss count would not do — the pipeline consults the resolver for every
event whose content is out of band, and an event that never had content is not a duplicate consumer.

#### Scenario: A repeated resolution is counted
- **WHEN** content for an event is resolved and then requested again
- **THEN** the repeat count increases

#### Scenario: An ordinary miss is not a repeat
- **WHEN** content is requested for an event that never had any
- **THEN** the repeat count does not change
