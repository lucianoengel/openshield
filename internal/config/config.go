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
	"path/filepath"
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
	// KindUnitInterval is a probability-like value in [0,1). It exists because a THRESHOLD compared
	// against a squashed score is silently unreachable when set at or above the ceiling: the detector
	// runs, scores every subject, and can never alert. That is the "a typo quietly disables a feature"
	// failure PLAT-5 was built to refuse, and a range is the only thing that catches it.
	KindUnitInterval Kind = "unit_interval"
	// KindSecret is a CREDENTIAL. It is a kind rather than a naming convention so redaction is a property
	// of the field, not of whether someone remembered to call the variable *_TOKEN.
	KindSecret Kind = "secret"
	// KindPath is a filesystem path — rendered as a file picker, and never redacted (a path is not a
	// credential, and hiding it makes misconfiguration undiagnosable).
	KindPath Kind = "path"
	// KindOutputPath is a path the OPERATOR DOES NOT SUPPLY — either one the product creates (a spool
	// directory, a state file) or one another component creates and this one connects to (an IPC
	// socket). Validated on its PARENT being usable, never on its own existence.
	//
	// The distinction is not pedantry (D318). OPENSHIELD_QUEUE_DIR was declared KindPath, so startup
	// demanded that the spool directory already exist while `queue.Open` did MkdirAll on it two hundred
	// lines later: the configuration layer refused to boot without something the code would have created
	// itself. Every other KindPath field is a key, a policy or a baseline the operator PROVIDES, where
	// requiring existence is exactly right — which is why the wrong kind here went unnoticed.
	//
	// The IPC-socket half is the same bug with a worse consequence (D321). Both ends of the exec-verdict
	// and print-verdict sockets were KindPath, so the ENGINE refused to start until the socket it was
	// about to create already existed — making the feature unreachable through configuration — and the
	// privileged GATE refused to start unless the engine was already up. That second one inverts the
	// contract the gate exists to honour: it is built to tolerate a dead engine by failing OPEN, and
	// requiring the engine's socket at startup makes it fail CLOSED before it has run a line.
	KindOutputPath Kind = "output_path"
	// KindSocketPath is a unix socket path: an output path (one side creates it, the other connects)
	// that is additionally BOUNDED by the platform's `sockaddr_un` address limit.
	//
	// The bound is the whole reason this is a kind of its own, and it REVERSES D321 (D325). D321 met
	// this question and declined, because a socket kind then behaved identically to KindOutputPath and a
	// kind distinguished only by its name is noise in a schema that drives a UI. That was right; its
	// premise has changed. The two now differ in behaviour, and a behavioural difference is exactly what
	// earns a distinct kind.
	//
	// The alternative — a length check inside KindOutputPath keyed on the field's NAME ending in
	// `_SOCKET` — would put a behavioural rule in a string comparison, where the next setting called
	// something else silently gets no bound.
	//
	// What it catches: a path too long to bind, known from the VALUE ALONE, before anything is created.
	// What it deliberately does not: permissions, a full filesystem, a stale socket held by another
	// process. A configuration layer that pretended to predict a syscall's outcome would be wrong the
	// first time the two disagreed.
	KindSocketPath Kind = "socket_path"
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
	// Bound is the operational range beyond parseability: the check, the range as a person reads it,
	// and what a value outside it breaks. Nil means the Kind's parseability is the only constraint.
	//
	// A plain `func(raw string) error` lived here with no caller anywhere in the shipped tree until
	// SEC-A, which is why "is this a duration" was the entire bound on values that decide whether
	// anything is detected at all. It became a struct when the schema had to be RENDERABLE (D467): a
	// closure cannot be shown in a form, and declaring the range separately so it could be is how the
	// form and the server start disagreeing.
	Bound *Bound

	// Sensitivity says which way a change to this field moves the deployment's ability to DETECT, so
	// "this edit reduces coverage" is computable rather than something a reviewer has to know per key
	// (SEC-A). See sensitivity.go.
	Sensitivity Sensitivity

	// ZeroDisables marks a field whose zero value turns its feature OFF rather than meaning "as often as
	// possible" or "none". It changes how zero ORDERS: without it, setting a correlation interval to 0s
	// — which disables scheduled correlation entirely — would compare as the most aggressive possible
	// setting, and the one change that stops incidents being raised at all would score as a hardening.
	ZeroDisables bool
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

// ActiveOverrides is every dynamic field this process is taking from the ENVIRONMENT because
// break-glass named it (D317).
//
// The mirror of IgnoredOverrides, and the more important of the two. The scope split's promise is that
// an override "applies AND is reported" — but until D317 the process only announced the case where an
// env value was IGNORED, which is the harmless one. The consequential case, where a host is deliberately
// NOT running what the console says, was visible only to somebody who thought to query /config.
//
// That asymmetry is backwards: we shouted about the setting that does nothing and were silent about the
// one that changes behaviour. During an incident, "why is this host different" is asked of logs first.
func (r *Resolver) ActiveOverrides() []string {
	var out []string
	keys := breakGlassKeys()
	for _, key := range r.order {
		f := r.fields[key]
		if f.Scope != ScopeDynamic || !keys[key] {
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
		if f.Bound != nil {
			if err := f.Bound.Check(raw); err != nil {
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
	if (f.Kind == KindPath || f.Kind == KindOutputPath || f.Kind == KindSocketPath) && origin == "default" {
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
	case KindUnitInterval:
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("not a number")
		}
		if v < 0 || v >= 1 {
			return fmt.Errorf("must be in [0,1) — the score it is compared against is squashed to that "+
				"range, so %v can never be reached and the detector would run without ever alerting", v)
		}
	case KindPath:
		if _, err := os.Stat(raw); err != nil {
			return fmt.Errorf("path is not readable")
		}
	case KindOutputPath, KindSocketPath:
		// A socket is bounded by the kernel's address size, and the kernel does NOT truncate: it refuses
		// the bind with EINVAL, surfaced as "bind: invalid argument" — a message naming neither the
		// length nor the cause. Checked FIRST, because a too-long path is wrong regardless of what its
		// parent directory looks like, and the length is the more useful thing to be told.
		if f.Kind == KindSocketPath && len(raw) > MaxSocketPath {
			return fmt.Errorf("socket path is %d bytes, over this platform's %d-byte limit — the bind "+
				"would fail with \"invalid argument\", which names neither the length nor the cause",
				len(raw), MaxSocketPath)
		}
		// The PARENT must exist and be a directory. Checking the path itself would refuse a spool
		// directory that has simply not been created yet — which is every first boot — while checking
		// nothing at all would accept a typo that silently spools into an unwritable place.
		parent := filepath.Dir(raw)
		info, err := os.Stat(parent)
		if err != nil {
			return fmt.Errorf("the parent directory %s does not exist", parent)
		}
		if !info.IsDir() {
			return fmt.Errorf("the parent path %s is not a directory", parent)
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

	// Range and Why are the operational bound as a person reads it, and what a value outside it breaks
	// (D467). Empty when the field has no bound beyond its Kind.
	//
	// Without these a schema-driven form offers no range and no help, so an operator learns the bound by
	// typing a value and having it refused — and the refusal is the one place the consequence was
	// written, which means the sentence explaining WHY reached them only after they had already chosen
	// the wrong thing.
	Range string `json:"range,omitempty"`
	Why   string `json:"why,omitempty"`

	// Sensitivity is which direction of change reduces what the deployment can detect, as a name
	// ("raising_weakens", "lowering_weakens", "any_change_weakens"), or empty when the field does not
	// gate detection or retention.
	//
	// The server remains authoritative on whether a given change weakened — it records that per change
	// and alerts on it. This is the LABEL, so a form can say which way the dangerous direction runs
	// BEFORE the change is made rather than after. A console that cannot show it is a console in which
	// the most consequential settings look like all the others.
	Sensitivity string `json:"sensitivity,omitempty"`

	// ZeroDisables says the zero value turns the feature OFF rather than meaning "as often as possible".
	// A form that does not say so presents the single most dangerous value as an ordinary end of the
	// range — it is how OPENSHIELD_CORRELATE_INTERVAL=0s reads as the most aggressive setting available.
	ZeroDisables bool `json:"zero_disables,omitempty"`
}

// Describe returns the schema, derived from the field declarations. This is the UI's data source.
func (r *Resolver) Describe() []FieldDesc {
	out := make([]FieldDesc, 0, len(r.order))
	for _, key := range r.order {
		f := r.fields[key]
		d := FieldDesc{Key: f.Key, Scope: f.Scope, Kind: f.Kind, Description: f.Description, Secret: f.Secret(),
			ZeroDisables: f.ZeroDisables}
		if f.Bound != nil {
			d.Range, d.Why = f.Bound.Range, f.Bound.Why
		}
		if f.Sensitivity != NotSensitive {
			d.Sensitivity = f.Sensitivity.String()
		}
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
// DBRevision is the stored-configuration revision this resolver has loaded — the answer to "has this
// host caught up with my change", which is a different question from "what is the latest revision".
func (r *Resolver) DBRevision() int64 {
	if r.DB == nil {
		return 0
	}
	return r.DB.Revision()
}

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
	if f.Bound != nil {
		return f.Bound.Check(raw)
	}
	return nil
}
