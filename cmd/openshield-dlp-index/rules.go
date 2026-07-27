package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// SIGNING CUSTOM RULE BUNDLES (D297).
//
// The worker VERIFIES signed rule bundles and refuses unverified ones — a fail-closed path built in
// HON-1/D100 and wired, with `OPENSHIELD_RULES_BUNDLE` and `OPENSHIELD_RULES_PUBKEY` both read. Nothing
// in the product SIGNED one. `classify.SignRuleBundle` carried the comment "this is the operator-
// authoring side" and had no caller, so the authoring side did not exist: an operator could configure
// the verification, and could not produce the artifact it verifies.
//
// It lives in this tool rather than a new one because it is the same job with the same key: this binary
// already builds and signs the operator's OTHER trusted detection data (the EDM/record/IDM indexes),
// and its `keygen` already mints the Ed25519 keypair. A second tool would mean a second key to manage
// for no reason.
//
// RULES ARE VALIDATED AT AUTHORING TIME, by compiling them through the SAME path the worker uses. An
// operator learns their regex does not compile when they write it, not when a worker silently falls back
// to built-ins in production — the same discipline the configuration surface follows for settings.

// ruleSpec is the operator-facing JSON. Deliberately not the protobuf wire format: an operator should
// write a pattern and a confidence, not a serialized message, and the validator is a NAME rather than an
// enum number so the file is readable and reviewable in a pull request.
type ruleSpec struct {
	RuleID     uint32  `json:"rule_id"`
	Pattern    string  `json:"pattern"`
	Confidence float64 `json:"confidence"`
	Validator  string  `json:"validator,omitempty"` // none | luhn
}

// validatorByName is the CLOSED vocabulary an operator may name. A rule file cannot introduce a
// validator — the validators are built in, never operator-supplied code (D14's discipline applied to
// detection: configuration selects from a fixed set, it does not extend the program).
var validatorByName = map[string]corev1.RuleValidator{
	"":     corev1.RuleValidator_RULE_VALIDATOR_NONE,
	"none": corev1.RuleValidator_RULE_VALIDATOR_NONE,
	"luhn": corev1.RuleValidator_RULE_VALIDATOR_LUHN,
}

func rules(args []string) {
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	in := fs.String("in", "", "rule file (JSON array of {rule_id, pattern, confidence, validator})")
	keyPath := fs.String("key", "", "operator Ed25519 private key file (64 bytes)")
	out := fs.String("out", "", "output signed rule-bundle file")
	_ = fs.Parse(args)
	if *in == "" || *keyPath == "" || *out == "" {
		fatal("rules needs --in, --key and --out")
	}

	raw, err := os.ReadFile(*in)
	if err != nil {
		fatal("reading %s: %v", *in, err)
	}
	var specs []ruleSpec
	dec := json.NewDecoder(newBytesReader(raw))
	// An unknown field is a refusal: a typo'd "confidance" would otherwise silently produce a rule with
	// zero confidence, which the compiler then rejects with a message about a number the operator never
	// wrote.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&specs); err != nil {
		fatal("parsing %s: %v", *in, err)
	}
	if len(specs) == 0 {
		fatal("%s defines no rules — signing an empty bundle would produce an artifact that loads nothing", *in)
	}

	bundle := &corev1.RuleBundle{}
	for i, sp := range specs {
		v, ok := validatorByName[sp.Validator]
		if !ok {
			fatal("rule %d: %q is not a validator (want none or luhn)", i, sp.Validator)
		}
		bundle.Rules = append(bundle.Rules, &corev1.DetectorRule{
			RuleId: sp.RuleID, Pattern: sp.Pattern, Confidence: sp.Confidence, Validator: v,
		})
	}

	key, err := os.ReadFile(*keyPath)
	if err != nil {
		fatal("reading key %s: %v", *keyPath, err)
	}
	if len(key) != ed25519.PrivateKeySize {
		fatal("key %s is %d bytes, want %d (raw Ed25519 private key)", *keyPath, len(key), ed25519.PrivateKeySize)
	}
	signed, err := classify.SignRuleBundle(bundle, ed25519.PrivateKey(key))
	if err != nil {
		fatal("signing bundle: %v", err)
	}

	// COMPILE IT BEFORE WRITING IT, through the worker's own loader. A bundle that does not load is one
	// the operator finds out about in production, where the worker fails closed to built-ins and their
	// custom detection is silently absent.
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	loaded, err := classify.LoadSignedRules(signed, pub)
	if err != nil {
		fatal("the bundle does not load: %v", err)
	}

	if err := os.WriteFile(*out, signed, 0o644); err != nil {
		fatal("writing %s: %v", *out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote signed rule bundle %s (%d rule(s), all compiled). Give it to the "+
		"worker as OPENSHIELD_RULES_BUNDLE, with the public key as OPENSHIELD_RULES_PUBKEY.\n",
		*out, len(loaded))
}
