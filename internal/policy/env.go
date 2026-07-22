package policy

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// SelectFromEnv builds the policy Stage from the OPENSHIELD_POLICY_* environment:
//
//   - OPENSHIELD_POLICY_PACK   — a single compliance pack (pci|hipaa|gdpr), back-compat
//   - OPENSHIELD_POLICY_PACKS  — comma-separated packs
//   - OPENSHIELD_POLICY_CUSTOM — path to an operator Rego file
//
// Packs and the custom module COMPOSE WITH the default policy (DLP-5b/ADR-5) — selecting a
// pack never disables the default's protections (behavioral alerting, strong-detector alert),
// the silent-disable this replaces. With none set, it returns the plain observe-only default.
// An unknown pack name aborts — a compliance control must not silently fall back to permissive.
func SelectFromEnv(ctx context.Context) (*Stage, error) {
	names := parsePackNames(os.Getenv("OPENSHIELD_POLICY_PACK"), os.Getenv("OPENSHIELD_POLICY_PACKS"))
	custom := ""
	if p := os.Getenv("OPENSHIELD_POLICY_CUSTOM"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("policy: reading OPENSHIELD_POLICY_CUSTOM %q: %w", p, err)
		}
		custom = string(b)
	}
	if len(names) == 0 && custom == "" {
		return NewDefault(ctx)
	}
	return NewComposite(ctx, names, custom)
}

// parsePackNames merges the singular and comma-list env values into an ordered,
// de-duplicated pack list (empties dropped) so PACK=pci + PACKS=pci,hipaa yields
// [pci, hipaa], not a duplicate.
func parsePackNames(single, list string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	add(single)
	for _, n := range strings.Split(list, ",") {
		add(n)
	}
	return out
}

// Bundle reports the composed bundle identity stamped on this stage's Decisions
// (e.g. "default+pci+hipaa"), for startup logging.
func (s *Stage) Bundle() string { return s.version }
