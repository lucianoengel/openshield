package policy

import (
	"context"
	_ "embed"
	"fmt"
	"sort"
)

//go:embed default.rego
var defaultPolicy string

//go:embed packs/pci.rego
var pciPack string

//go:embed packs/hipaa.rego
var hipaaPack string

//go:embed packs/gdpr.rego
var gdprPack string

// compliancePacks are the ready-made regulatory policy templates (DLP-5): a hand-written default
// only alerted on CPF/credit-card, so shipping PCI/HIPAA/GDPR packs makes the classifier's detector
// breadth usable as compliance controls without the operator authoring Rego. Each is observe-only
// (ALERT, never BLOCK) and keyed on the detector types in that regulation's scope.
var compliancePacks = map[string]string{
	"pci":   pciPack,
	"hipaa": hipaaPack,
	"gdpr":  gdprPack,
}

// Packs returns the available compliance-pack names, sorted.
func Packs() []string {
	names := make([]string, 0, len(compliancePacks))
	for n := range compliancePacks {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// NewPack prepares a named compliance pack (pci|hipaa|gdpr). An unknown name is an error, never a
// silent fallback to a permissive policy — a compliance control that quietly became "allow all"
// would be worse than none. The id/version stamped on the Decision records which pack applied.
func NewPack(ctx context.Context, name string) (*Stage, error) {
	module, ok := compliancePacks[name]
	if !ok {
		return nil, fmt.Errorf("policy: unknown compliance pack %q (have %v)", name, Packs())
	}
	return New(ctx, "openshield.pack."+name, "dlp5-1", module)
}

// DefaultID and DefaultVersion identify the embedded Phase-1 policy. They are
// stamped onto every Decision so the ledger records which policy produced it —
// the precondition for replaying against the right policy.
const (
	DefaultID      = "openshield.default"
	DefaultVersion = "phase1-1"
)

// NewDefault prepares the embedded observe-only policy.
func NewDefault(ctx context.Context) (*Stage, error) {
	return New(ctx, DefaultID, DefaultVersion, defaultPolicy)
}
