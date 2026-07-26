## ADDED Requirements

### Requirement: The incidents read surface can select a correlation rule

The incidents endpoint SHALL accept an optional rule selector so an operator can ask for the
cross-domain entity rule instead of the default single-domain burst rule, with its own parameters
(minimum distinct domains, and an optional ordered domain sequence). Omitting the selector SHALL behave
exactly as before — the burst rule, unchanged — so no existing client's request changes meaning.

A malformed rule name, domain minimum, or sequence SHALL be refused with 400 rather than silently
defaulted. A silently-ignored bad parameter returns a wider result set that looks authoritative, which is
the failure mode the existing correlation parameters are already guarded against.

The read surface SHALL remain operator-gated, and rule parameters SHALL be bound as data, never
interpolated into the query.

#### Scenario: The default response is unchanged
- **WHEN** an operator requests incidents with no rule selector
- **THEN** the response is the burst-rule result, identical to the behavior before the cross-domain rule
  existed

#### Scenario: The cross-domain rule is selectable
- **WHEN** an operator requests incidents with the cross-domain rule and a minimum of two domains
- **THEN** the response contains the entity-keyed cross-domain incidents for that threshold

#### Scenario: A malformed rule parameter is refused
- **WHEN** an operator requests incidents with an unknown rule name or a non-numeric domain minimum
- **THEN** the request is refused with 400 rather than falling back to a default rule or threshold
