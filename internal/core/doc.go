// Package core holds the fixed pipeline:
//
//	Event → Classification → Policy → Decision → Enforcement → Audit → Investigation → Analytics
//
// The pipeline does not change. New capabilities arrive as new Event producers,
// Classifiers, Policies and Enforcers. A change that requires editing this package
// is a design failure, not a feature — see docs/decisions.md (D7) and the CI
// fitness test (T-014).
//
// core must not import internal/connectors or internal/enforcers. Dependencies
// point inward; plugins register themselves with core, never the reverse.
package core
