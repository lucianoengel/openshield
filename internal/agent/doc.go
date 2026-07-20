// Package agent is the endpoint agent.
//
// The agent is deliberately split across two OS processes (docs/decisions.md D13):
//
//   - a privileged process holding the fanotify hooks, which NEVER parses
//     attacker-controlled bytes;
//   - an unprivileged, sandboxed worker that does all content parsing and returns
//     only structured verdicts over IPC.
//
// The precedent for this being mandatory rather than tidy: ClamAV CVE-2025-20260,
// a PDF-parser heap overflow reachable in a privileged daemon. A root process with
// CAP_SYS_ADMIN that also decodes untrusted documents is how a security tool makes
// a machine less secure.
//
// The privileged half's import set is enforced in CI (T-006): no encoding/*,
// compress/*, archive/* or parser packages may appear in its dependency graph.
package agent
