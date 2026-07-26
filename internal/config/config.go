// Package config is OpenShield's typed, validated, introspectable configuration (PLAT-5).
//
// THE CONSTRAINT THAT SHAPED THIS: configuration will eventually be set mostly in the UI (PLAT-1). That
// is why the schema is DERIVED from the same declarations the binary reads its values from, rather than
// maintained beside them. A hand-written schema for a UI fails in a specific, silent way — the form offers
// a field the binary never reads, an operator sets it, nothing happens, and nobody finds out until an
// incident. Deriving it makes that structurally impossible.
//
// Three more properties exist for the same reason:
//
//   - SECRETS ARE NEVER READABLE BACK. A secret field reports set/unset and never its value, anywhere. An
//     interface that can render a stored credential into a form field is an exfiltration path that looks
//     like a feature.
//   - ERRORS ARE FIELD-SCOPED AND REPORTED TOGETHER. An operator fixing five variables should not need
//     five boots, and a UI needs to attach each message to an input.
//   - SOURCES ARE AN INTERFACE. A DB source written by the UI slots in below env later, without touching a
//     single call site — and env staying on top means an operator can override a UI-set value on one host
//     during an incident, without a database.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Kind is what a field holds — and what a UI would render it as.
type Kind string

const (
	KindString   Kind = "string"
	KindInt      Kind = "int"
	KindDuration Kind = "duration"
	KindBool     Kind = "bool"
	// KindSecret is a CREDENTIAL. It is a kind rather than a naming convention so redaction is a property
	// of the field, not of whether someone remembered to call the variable *_TOKEN.
	KindSecret Kind = "secret"
	// KindPath is a filesystem path — rendered as a file picker, and never redacted (a path is not a
	// credential, and hiding it makes misconfiguration undiagnosable).
	KindPath Kind = "path"
)

// Field is ONE declaration, used for both reading and describing. There is deliberately no second list.
//
// Declared as values with real Go functions rather than via struct tags and reflection: a tag is a string
// literal the compiler cannot check, a typo in one is a runtime surprise, and a validator expressed as tag
// syntax is a small language to reimplement. More lines, checked by the compiler, and a validator is code.
type Field struct {
	Key         string
	Scope       Scope
	Kind        Kind
	Default     string
	Description string
	// Validate is an optional extra constraint beyond parseability, returning why the value is refused.
	Validate func(raw string) error
}

// Secret reports whether this field's value must never be read back.
func (f Field) Secret() bool { return f.Kind == KindSecret }

// FieldError is one problem, scoped to the field that caused it, so a UI can show it inline.
type FieldError struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"` // omitted for a secret — see newFieldError
	Reason string `json:"reason"`
}

func (e FieldError) Error() string {
	if e.Value == "" {
		return fmt.Sprintf("%s: %s", e.Key, e.Reason)
	}
	return fmt.Sprintf("%s=%q: %s", e.Key, e.Value, e.Reason)
}

// newFieldError builds an error that NEVER carries a secret's value — an error message is an output path
// like any other, and a rejected credential in a log is still a leaked credential.
func newFieldError(f Field, raw, reason string) FieldError {
	e := FieldError{Key: f.Key, Reason: reason}
	if !f.Secret() {
		e.Value = raw
	}
	return e
}

// Errors is every problem found, together. Failing on the first would make an operator fix configuration
// one boot at a time.
type Errors []FieldError

func (e Errors) Error() string {
	parts := make([]string, 0, len(e))
	for _, fe := range e {
		parts = append(parts, fe.Error())
	}
	return "invalid configuration:\n  " + strings.Join(parts, "\n  ")
}

// Source supplies raw values. It is an interface so a DB-backed source (written by the UI) can be added
// without changing how any value is read.
type Source interface {
	Name() string
	Lookup(key string) (string, bool)
}

// EnvSource reads the process environment.
type EnvSource struct{}

func (EnvSource) Name() string { return "env" }
func (EnvSource) Lookup(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// FileSource reads KEY=VALUE lines, `#` comments and blanks ignored.
type FileSource struct {
	path string
	m    map[string]string
}

func (f *FileSource) Name() string { return "file:" + f.path }
func (f *FileSource) Lookup(key string) (string, bool) {
	v, ok := f.m[key]
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// LoadFile reads a config file. A missing file is NOT an error — the file source is optional and the
// deployment may configure entirely through the environment.
func LoadFile(path string) (*FileSource, error) {
	f := &FileSource{path: path, m: map[string]string{}}
	fh, err := os.Open(path)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		eq := strings.Index(text, "=")
		if eq <= 0 {
			return nil, fmt.Errorf("config: %s line %d: want KEY=VALUE, got %q", path, line, text)
		}
		f.m[strings.TrimSpace(text[:eq])] = strings.TrimSpace(text[eq+1:])
	}
	return f, sc.Err()
}

// Resolver reads fields from ordered sources.
//
// PRECEDENCE: sources are consulted IN ORDER, and the declared default is the last resort. Callers put env
// first — that preserves today's behaviour and the container idiom, and it means an operator can override
// a UI-set value on a single host during an incident without touching a database.
type Resolver struct {
	// Sources serve BOOTSTRAP fields, in order (env, then an optional file, then the declared default).
	Sources []Source
	// DB is the ONLY source for a DYNAMIC field. Nil means none is attached yet, and every dynamic field
	// falls back to its declared default — which is what a deployment that has never written a setting
	// should get, rather than a failure.
	DB     *DBSource
	fields map[string]Field
	order  []string
}

// New builds a resolver over a field set. A duplicate key is a programming error and panics: two
// declarations for one key is exactly the drift this package exists to prevent, and it is not something to
// discover at runtime on one code path.
func New(fields []Field, sources ...Source) *Resolver {
	r := &Resolver{Sources: sources, fields: make(map[string]Field, len(fields))}
	for _, f := range fields {
		if _, dup := r.fields[f.Key]; dup {
			panic("config: duplicate field declaration for " + f.Key)
		}
		r.fields[f.Key] = f
		r.order = append(r.order, f.Key)
	}
	return r
}

// raw returns a key's value and the name of the source that supplied it.
//
// THE SPLIT LIVES HERE. A bootstrap field reads env → file → default. A dynamic field reads the DATABASE,
// then its default — and NOT the environment, because an env value that silently shadowed a stored one is
// exactly how a console and a host come to disagree with no signal.
//
// The one exception is explicit and reported: a field named in OPENSHIELD_BREAKGLASS takes its env value,
// and Effective() labels it an override so nobody has to guess why a host differs.
func (r *Resolver) raw(key string) (value, origin string) {
	f, ok := r.fields[key]
	if !ok {
		// An undeclared key cannot be read. This is the other half of "the schema is derived": code that
		// reads a field nobody declared would be invisible to the UI, so it must not be possible.
		panic("config: read of undeclared field " + key)
	}
	if f.Scope == ScopeDynamic {
		if v, ok := r.envOverride(f); ok {
			return v, "env(break-glass)"
		}
		if r.DB != nil {
			if v, ok := r.DB.Lookup(key); ok {
				return v, "db"
			}
		}
		return f.Default, "default"
	}
	for _, s := range r.Sources {
		if v, ok := s.Lookup(key); ok {
			return v, s.Name()
		}
	}
	return f.Default, "default"
}

// envOverride reports a break-glass env value for a dynamic field.
func (r *Resolver) envOverride(f Field) (string, bool) {
	if f.Scope != ScopeDynamic || !breakGlassKeys()[f.Key] {
		return "", false
	}
	v, ok := os.LookupEnv(f.Key)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// IgnoredOverrides lists dynamic fields set in the environment WITHOUT break-glass. They do not take
// effect — and they are reported, at boot and in the effective output, because the operator who set one
// believes it is doing something.
func (r *Resolver) IgnoredOverrides() []string {
	var out []string
	for _, key := range r.order {
		f := r.fields[key]
		if f.Scope != ScopeDynamic || breakGlassKeys()[key] {
			continue
		}
		if v, ok := os.LookupEnv(key); ok && v != "" {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// String returns a field's effective value.
func (r *Resolver) String(key string) string { v, _ := r.raw(key); return v }

// Int returns a field's value as an integer. It assumes Validate has run — a malformed value is refused at
// boot, so a reader never has to decide what to do with one.
func (r *Resolver) Int(key string) int {
	n, _ := strconv.Atoi(r.String(key))
	return n
}

// Duration returns a field's value as a duration.
func (r *Resolver) Duration(key string) time.Duration {
	d, _ := time.ParseDuration(r.String(key))
	return d
}

// Bool returns a field's value as a boolean.
func (r *Resolver) Bool(key string) bool {
	b, _ := strconv.ParseBool(r.String(key))
	return b
}

// Validate checks EVERY field and returns EVERY problem.
//
// It never returns early: an operator fixing five variables should not need five boots, and a UI needs one
// message per input rather than the first one it hit.
func (r *Resolver) Validate() error {
	var errs Errors
	for _, key := range r.order {
		f := r.fields[key]
		raw, origin := r.raw(key)
		if raw == "" {
			continue // unset and no default: the reader's own required-ness check applies
		}
		if err := parseForOrigin(f, raw, origin); err != nil {
			errs = append(errs, newFieldError(f, raw, err.Error()+" (from "+origin+")"))
			continue
		}
		if f.Validate != nil {
			if err := f.Validate(raw); err != nil {
				errs = append(errs, newFieldError(f, raw, err.Error()+" (from "+origin+")"))
			}
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// parseForOrigin is parseFor, plus the one check that depends on WHERE a value came from.
//
// A KindPath field is checked for existence only when it was EXPLICITLY SET. A path that came from the
// DECLARED DEFAULT and does not exist is normal — it names where a feature's file WOULD live, and the
// feature simply is not in use — whereas a path an operator typed and got wrong is worth failing the boot
// over. Statting a default conflates "is this a path" with "does this file exist right now", which is
// also a snapshot: a path readable at boot can stop being readable an hour later, so the check must not
// be mistaken for a guarantee. The reader gives the real error at the point of use.
func parseForOrigin(f Field, raw, origin string) error {
	if f.Kind == KindPath && origin == "default" {
		return nil
	}
	return parseFor(f, raw)
}

// parseFor is the kind's parseability check. A malformed value is an ERROR, never a silent fall back to
// the default — the silent fallback is what let a typo'd interval quietly disable scheduled correlation.
func parseFor(f Field, raw string) error {
	switch f.Kind {
	case KindInt:
		if _, err := strconv.Atoi(raw); err != nil {
			return fmt.Errorf("not an integer")
		}
	case KindDuration:
		if _, err := time.ParseDuration(raw); err != nil {
			return fmt.Errorf("not a duration (want e.g. 30s, 5m, 1h)")
		}
	case KindBool:
		if _, err := strconv.ParseBool(raw); err != nil {
			return fmt.Errorf("not a boolean")
		}
	case KindPath:
		if _, err := os.Stat(raw); err != nil {
			return fmt.Errorf("path is not readable")
		}
	}
	return nil
}

// FieldDesc is one field as a UI would render it. IT CARRIES NO VALUE — only the declaration.
type FieldDesc struct {
	Key         string `json:"key"`
	Scope       Scope  `json:"scope"`
	Kind        Kind   `json:"kind"`
	Default     string `json:"default,omitempty"`
	Description string `json:"description"`
	Secret      bool   `json:"secret"`
}

// Describe returns the schema, derived from the field declarations. This is the UI's data source.
func (r *Resolver) Describe() []FieldDesc {
	out := make([]FieldDesc, 0, len(r.order))
	for _, key := range r.order {
		f := r.fields[key]
		d := FieldDesc{Key: f.Key, Scope: f.Scope, Kind: f.Kind, Description: f.Description, Secret: f.Secret()}
		if !f.Secret() {
			// A secret's DEFAULT is not shown either: a default credential is a credential.
			d.Default = f.Default
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// EffectiveValue is one resolved setting and where it came from.
//
// Value is EMPTY for a secret, always — Set is the only thing reported. There is no flag to turn that off,
// because the moment there is one, something will pass it.
type EffectiveValue struct {
	Key    string `json:"key"`
	Scope  Scope  `json:"scope"`
	Kind   Kind   `json:"kind"`
	Value  string `json:"value,omitempty"`
	Set    bool   `json:"set"`
	Origin string `json:"origin"`
	Secret bool   `json:"secret"`
}

// Effective returns what this process is actually honouring, with each value's origin — the answer to
// "what is this binary running with", which today requires reading the unit file and guessing.
func (r *Resolver) Effective() []EffectiveValue {
	out := make([]EffectiveValue, 0, len(r.order))
	for _, key := range r.order {
		f := r.fields[key]
		raw, origin := r.raw(key)
		ev := EffectiveValue{Key: key, Scope: f.Scope, Kind: f.Kind, Set: raw != "", Origin: origin, Secret: f.Secret()}
		if !f.Secret() {
			ev.Value = raw
		}
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Keys is every declared key, for the adoption test that asserts nothing is read without being declared.
func (r *Resolver) Keys() []string {
	out := append([]string(nil), r.order...)
	sort.Strings(out)
	return out
}

// WriteEffective renders the effective configuration for an operator. Secrets show as "(set)"/"(unset)".
func (r *Resolver) WriteEffective(w io.Writer) {
	for _, ev := range r.Effective() {
		switch {
		case ev.Secret && ev.Set:
			fmt.Fprintf(w, "%-44s (set)      [%s]\n", ev.Key, ev.Origin)
		case ev.Secret:
			fmt.Fprintf(w, "%-44s (unset)\n", ev.Key)
		case !ev.Set:
			fmt.Fprintf(w, "%-44s (unset)\n", ev.Key)
		default:
			fmt.Fprintf(w, "%-44s %-24s [%s]\n", ev.Key, ev.Value, ev.Origin)
		}
	}
}

// Field returns a declaration, so the write path can validate a proposed value against the SAME
// declaration the reader uses — there is no second copy of a field's contract.
func (r *Resolver) Field(key string) (Field, bool) {
	f, ok := r.fields[key]
	return f, ok
}

// Check validates ONE proposed value against its declaration, for a write path that must refuse a bad
// value at the moment an operator types it rather than at the next restart.
func (f Field) Check(raw string) error {
	if err := parseFor(f, raw); err != nil {
		return err
	}
	if f.Validate != nil {
		return f.Validate(raw)
	}
	return nil
}
