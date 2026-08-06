# e2e-verification

## ADDED Requirements

### Requirement: A test stops the background work it starts

A test that starts a goroutine against a resource the test harness owns SHALL wait for that goroutine to
have RETURNED before the resource is released, and SHALL fail rather than hang if it does not. Cancelling
a context is a request, not a stop: it returns while the goroutine may still be inside a query.

A loop still running after its test finished writes into whatever it was given — a closed pool, a
package-level counter, the next test's schema — and the test it breaks is not the test that leaked it.
This is the only defect class in the suite whose blast radius is another file.

Where a test asserts on a counter that is shared across the package, it SHALL assert on the value as it
stands rather than resetting it first, and its failure message SHALL say that the count may belong to a
loop another test leaked. Resetting turns a cross-test leak into a silence, and makes the assertion pass
whether or not the leak exists.

#### Scenario: The loop is gone before the pool is
- **WHEN** a scenario starts a scheduled loop against the test's database
- **THEN** the loop has returned before the pool is closed, so no tick can run against it

#### Scenario: A leak is reported, not absorbed
- **WHEN** a background loop from an earlier test has counted a failure
- **THEN** the test asserting that counter fails and names the leak as a possible cause
