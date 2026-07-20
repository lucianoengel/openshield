// Package connectors holds Event producers — the only thing a connector does is
// publish Events. Connectors never classify, never decide and never enforce.
//
// Adding a connector must produce zero diffs in internal/core (T-014). Note the
// known weakness of that test: a connector structurally similar to an existing one
// proves little. See docs/decisions.md and the peer-UEBA paper design (T-004) for
// the harder test of the same claim.
package connectors
