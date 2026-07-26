package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/config"
)

// PLAT-5. The properties under test are the ones the UI constraint forces: the schema is derived from
// what the code reads, a secret is never readable back, and every problem is reported at once and scoped
// to its field.

func testFields() []config.Field {
	return []config.Field{
		{Key: "T_STRING", Kind: config.KindString, Default: "hello", Description: "a string"},
		{Key: "T_INT", Kind: config.KindInt, Default: "3", Description: "an int"},
		{Key: "T_DURATION", Kind: config.KindDuration, Default: "5m", Description: "a duration"},
		{Key: "T_BOOL", Kind: config.KindBool, Default: "false", Description: "a bool"},
		{Key: "T_SECRET", Kind: config.KindSecret, Default: "", Description: "a credential"},
	}
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "openshield.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPrecedenceAndOrigin — env over file over default, and each value says where it came from.
func TestPrecedenceAndOrigin(t *testing.T) {
	path := writeFile(t, "# a comment\nT_STRING=from-file\nT_INT=9\n")
	fs, err := config.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("T_STRING", "from-env")
	r := config.New(testFields(), config.EnvSource{}, fs)

	if got := r.String("T_STRING"); got != "from-env" {
		t.Errorf("T_STRING = %q, want the ENV value — an operator must be able to override a stored "+
			"value on one host during an incident, without a database", got)
	}
	if got := r.Int("T_INT"); got != 9 {
		t.Errorf("T_INT = %d, want the file value 9", got)
	}
	if got := r.Duration("T_DURATION"); got.String() != "5m0s" {
		t.Errorf("T_DURATION = %v, want the declared default", got)
	}
	origins := map[string]string{}
	for _, ev := range r.Effective() {
		origins[ev.Key] = ev.Origin
	}
	if origins["T_STRING"] != "env" || !strings.HasPrefix(origins["T_INT"], "file:") ||
		origins["T_DURATION"] != "default" {
		t.Errorf("origins = %v — 'what is this process running with' must be answerable", origins)
	}
	// A missing file is not an error: the file source is optional.
	if _, err := config.LoadFile(filepath.Join(t.TempDir(), "absent.conf")); err != nil {
		t.Errorf("a missing config file was an error: %v", err)
	}
}

// TestMalformedValueIsAnErrorNotASilentDefault.
//
// This is the behaviour change the ticket exists for: a typo'd OPENSHIELD_CORRELATE_INTERVAL silently
// disabled scheduled correlation, because the helper fell back to the default on a parse failure.
//
// Mutation: fall back to the default when parsing fails → no error → FAILS.
func TestMalformedValueIsAnErrorNotASilentDefault(t *testing.T) {
	t.Setenv("T_DURATION", "5 minutes")
	r := config.New(testFields(), config.EnvSource{})
	err := r.Validate()
	if err == nil {
		t.Fatal("a malformed duration validated — a silent fall back to the default is how a typo " +
			"disables a feature nobody notices is off")
	}
	if !strings.Contains(err.Error(), "T_DURATION") || !strings.Contains(err.Error(), "not a duration") {
		t.Errorf("error %q does not name the field and the constraint", err)
	}
	if !strings.Contains(err.Error(), "from env") {
		t.Errorf("error %q does not say WHICH SOURCE supplied the bad value", err)
	}
}

// TestEveryInvalidFieldIsReported — an operator fixing five variables should not need five boots, and a
// UI needs one message per input.
//
// Mutation: return on the first error → only one field is named → FAILS.
func TestEveryInvalidFieldIsReported(t *testing.T) {
	t.Setenv("T_INT", "many")
	t.Setenv("T_DURATION", "soon")
	t.Setenv("T_BOOL", "maybe")
	r := config.New(testFields(), config.EnvSource{})
	err := r.Validate()
	if err == nil {
		t.Fatal("three invalid fields validated")
	}
	var errs config.Errors
	if !asErrors(err, &errs) {
		t.Fatalf("error is not field-scoped: %T", err)
	}
	if len(errs) != 3 {
		t.Fatalf("reported %d problems %v, want 3 — failing on the first makes an operator fix "+
			"configuration one boot at a time", len(errs), errs)
	}
	seen := map[string]bool{}
	for _, fe := range errs {
		seen[fe.Key] = true
		if fe.Reason == "" {
			t.Errorf("%s has no reason — a UI cannot show a message it does not have", fe.Key)
		}
	}
	for _, k := range []string{"T_INT", "T_DURATION", "T_BOOL"} {
		if !seen[k] {
			t.Errorf("%s was not reported", k)
		}
	}
}

func asErrors(err error, out *config.Errors) bool {
	e, ok := err.(config.Errors)
	if ok {
		*out = e
	}
	return ok
}

// TestSecretIsNeverReadableBack is the property the UI constraint makes load-bearing: an interface that
// can render a stored credential into a form field is an exfiltration path that looks like a feature.
//
// Mutation: include the value in Effective() (or in Describe()'s default, or in a FieldError) → FAILS.
func TestSecretIsNeverReadableBack(t *testing.T) {
	const secret = "sup3r-s3cret-token-value"
	t.Setenv("T_SECRET", secret)
	r := config.New(testFields(), config.EnvSource{})

	// The reader can still USE it — redaction is about output paths, not about the value being unusable.
	if got := r.String("T_SECRET"); got != secret {
		t.Fatalf("the resolver cannot read its own secret: %q", got)
	}

	for name, body := range map[string]string{
		"Describe":  render(r.Describe()),
		"Effective": render(r.Effective()),
		"printed":   printed(r),
	} {
		if strings.Contains(body, secret) {
			t.Errorf("%s leaked the secret value:\n%s", name, body)
		}
	}
	// But it IS reported as set — "unset" and "set to something" must be distinguishable, or an operator
	// cannot tell a missing credential from a wrong one.
	var found bool
	for _, ev := range r.Effective() {
		if ev.Key == "T_SECRET" {
			found = ev.Set && ev.Secret && ev.Value == ""
		}
	}
	if !found {
		t.Error("a configured secret is not reported as set — an operator cannot tell it apart from missing")
	}
	if !strings.Contains(printed(r), "T_SECRET") || !strings.Contains(printed(r), "(set)") {
		t.Error("the printed output does not report the secret as set")
	}

	// And a REJECTED secret must not appear in the error either: an error message is an output path like
	// any other, and a rejected credential in a log is still a leaked credential.
	sf := []config.Field{{Key: "T_SECRET2", Kind: config.KindSecret, Description: "cred",
		Validate: func(string) error { return errBad }}}
	t.Setenv("T_SECRET2", secret)
	if err := config.New(sf, config.EnvSource{}).Validate(); err == nil {
		t.Fatal("the validator did not run")
	} else if strings.Contains(err.Error(), secret) {
		t.Errorf("a rejected secret's VALUE appears in the error: %v", err)
	}
}

var errBad = &staticErr{"refused"}

type staticErr struct{ s string }

func (e *staticErr) Error() string { return e.s }

func render(v any) string { return strings.ToLower(sprint(v)) }

func sprint(v any) string {
	var b bytes.Buffer
	switch t := v.(type) {
	case []config.FieldDesc:
		for _, d := range t {
			b.WriteString(d.Key + "|" + string(d.Kind) + "|" + d.Default + "|" + d.Description + "\n")
		}
	case []config.EffectiveValue:
		for _, e := range t {
			b.WriteString(e.Key + "|" + e.Value + "|" + e.Origin + "\n")
		}
	}
	return b.String()
}

func printed(r *config.Resolver) string {
	var b bytes.Buffer
	r.WriteEffective(&b)
	return b.String()
}

// TestSchemaCoversEveryReadableFieldInBothDirections — the anti-drift guard.
//
// A field that can be read but is not described would be invisible to a UI; a field described but not
// readable would be a form control that does nothing. Both are checked.
func TestSchemaCoversEveryReadableFieldInBothDirections(t *testing.T) {
	r := config.New(config.ServerFields, config.EnvSource{})
	described := map[string]bool{}
	for _, d := range r.Describe() {
		described[d.Key] = true
		if d.Description == "" {
			t.Errorf("%s has no description — a UI would render an unlabelled input", d.Key)
		}
	}
	for _, k := range r.Keys() {
		if !described[k] {
			t.Errorf("%s is readable but not described — invisible to a UI", k)
		}
	}
	if len(described) != len(r.Keys()) {
		t.Errorf("described %d fields but %d are readable", len(described), len(r.Keys()))
	}
}

// TestEveryServerEnvVarIsDeclared is the drift guard against the OTHER direction: a field read directly
// from the environment, bypassing the schema, would be a setting the UI can never show.
func TestEveryServerEnvVarIsDeclared(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "openshield-server", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, f := range config.ServerFields {
		declared[f.Key] = true
	}
	used := regexp.MustCompile(`OPENSHIELD_[A-Z0-9_]+`).FindAllString(string(src), -1)
	seen := map[string]bool{}
	for _, k := range used {
		if seen[k] {
			continue
		}
		seen[k] = true
		if !declared[k] {
			t.Errorf("%s is read by cmd/openshield-server but is NOT declared in ServerFields — it would "+
				"be invisible to the schema, and therefore to any UI built from it", k)
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no environment variables in the server source — the guard is not looking at the " +
			"right file, so it proves nothing")
	}
}

// TestDuplicateDeclarationPanics — two declarations for one key is exactly the drift this package exists
// to prevent, so it is a programming error, not a runtime surprise on one code path.
func TestDuplicateDeclarationPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a duplicate field declaration was accepted")
		}
	}()
	config.New([]config.Field{
		{Key: "T_DUP", Kind: config.KindString},
		{Key: "T_DUP", Kind: config.KindInt},
	})
}

// TestReadingAnUndeclaredFieldPanics — the other half of "the schema is derived": code reading a field
// nobody declared would be invisible to the UI, so it must not be possible.
func TestReadingAnUndeclaredFieldPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("an undeclared field was readable")
		}
	}()
	config.New(testFields()).String("T_NOT_DECLARED")
}

// TestEveryGatewayEnvVarIsDeclared — the same drift guard the server has (PLAT-5 follow-up). A field read
// directly from the environment, bypassing the schema, is a setting no UI can ever show.
func TestEveryGatewayEnvVarIsDeclared(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "openshield-gateway", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, f := range config.GatewayFields {
		declared[f.Key] = true
	}
	seen := map[string]bool{}
	for _, k := range regexp.MustCompile(`OPENSHIELD_[A-Z0-9_]+`).FindAllString(string(src), -1) {
		if seen[k] {
			continue
		}
		seen[k] = true
		if !declared[k] {
			t.Errorf("%s is read by cmd/openshield-gateway but is NOT declared in GatewayFields", k)
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no environment variables in the gateway source — the guard proves nothing")
	}
}

// TestTheGatewayNeedsNoDatabaseToReadItsConfiguration.
//
// Every gateway field is BOOTSTRAP, which is a statement about what the gateway is: a network appliance
// whose settings are node-local. It also means the most network-exposed component here never needs
// database credentials to read its own configuration — a property worth pinning, because the easy way to
// add a "fleet-wide gateway setting" later is to hand it a DSN.
func TestTheGatewayNeedsNoDatabaseToReadItsConfiguration(t *testing.T) {
	for _, f := range config.GatewayFields {
		if f.Scope != config.ScopeBootstrap {
			t.Errorf("%s is %s-scoped — the gateway would then need database credentials to read its "+
				"configuration; a fleet-wide gateway setting belongs on the SIGNED channel it already "+
				"verifies risk and intents on", f.Key, f.Scope)
		}
	}
	// And it resolves with no DB source attached at all.
	r := config.New(config.GatewayFields, config.EnvSource{})
	if got := r.String("OPENSHIELD_LISTEN"); got != "127.0.0.1:8080" {
		t.Errorf("resolving without a database gave %q", got)
	}
	if err := r.Validate(); err != nil {
		t.Errorf("the declared defaults do not validate: %v", err)
	}
}

// TestAnExplicitlySetBadPathStillFails — the other half of the default-path fix. A path an operator TYPED
// and got wrong is worth failing the boot over; only a path that came from the DECLARED DEFAULT is
// exempt, because that one names where a feature's file would live and the feature simply is not in use.
//
// Mutation: exempt every path, not just defaults → a typo'd path boots → FAILS.
func TestAnExplicitlySetBadPathStillFails(t *testing.T) {
	fields := []config.Field{{Key: "T_PATH", Kind: config.KindPath, Default: "/nonexistent/default",
		Description: "a path"}}
	// From the default: exempt, because the feature is simply not configured.
	if err := config.New(fields, config.EnvSource{}).Validate(); err != nil {
		t.Errorf("a DEFAULT path that does not exist failed validation: %v — that path names where a "+
			"feature's file would live, and the feature is not in use", err)
	}
	// Explicitly set and wrong: a typo, and worth failing the boot over.
	t.Setenv("T_PATH", "/definitely/not/here")
	if err := config.New(fields, config.EnvSource{}).Validate(); err == nil {
		t.Error("an explicitly-set path that does not exist validated — an operator who typed it wrong " +
			"finds out at first use instead of at boot")
	}
}

// TestEndpointEnvVarsAreDeclared — the drift guard for the two boundary components.
func TestEndpointEnvVarsAreDeclared(t *testing.T) {
	for _, tc := range []struct {
		cmd    string
		fields []config.Field
	}{
		{"openshield-agent", config.AgentFields},
		{"openshield-worker", config.WorkerFields},
	} {
		src, err := os.ReadFile(filepath.Join("..", "..", "cmd", tc.cmd, "main.go"))
		if err != nil {
			t.Fatal(err)
		}
		declared := map[string]bool{}
		for _, f := range tc.fields {
			declared[f.Key] = true
		}
		seen := map[string]bool{}
		for _, k := range regexp.MustCompile(`OPENSHIELD_[A-Z0-9_]+`).FindAllString(string(src), -1) {
			if seen[k] {
				continue
			}
			seen[k] = true
			if !declared[k] {
				t.Errorf("%s is read by cmd/%s but is NOT declared", k, tc.cmd)
			}
		}
		if len(seen) == 0 {
			t.Errorf("found no environment variables in cmd/%s — the guard proves nothing", tc.cmd)
		}
	}
}

// TestEndpointConfigNeedsNoDatabaseOrNetwork.
//
// A stronger requirement than the gateway's: the privileged agent's dependency ban exists because it
// never parses attacker-controlled bytes, and the worker's seccomp filter DENIES network. A config layer
// needing either would be unusable in both — so every field here is bootstrap, and the package stays
// stdlib-only. `make all` proves the dependency half; this proves the scope half.
func TestEndpointConfigNeedsNoDatabaseOrNetwork(t *testing.T) {
	for name, fields := range map[string][]config.Field{
		"agent": config.AgentFields, "worker": config.WorkerFields,
	} {
		for _, f := range fields {
			if f.Scope != config.ScopeBootstrap {
				t.Errorf("%s field %s is %s-scoped — reading it would require a database the %s must not "+
					"reach", name, f.Key, f.Scope, name)
			}
		}
		if err := config.New(fields, config.EnvSource{}).Validate(); err != nil {
			t.Errorf("%s defaults do not validate: %v", name, err)
		}
	}
}
