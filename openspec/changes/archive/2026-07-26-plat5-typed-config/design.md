## Context

Configuration today is ~50 direct `os.Getenv` calls with inline defaults and helpers (`env`, `envInt`,
`envDuration`) that silently fall back on a parse failure. There is no schema, no validation, and no way to
ask a running binary what it is honouring.

The owner's constraint — **configuration will eventually be set mostly in the UI** — is what makes this
more than a tidy-up. A UI needs a schema, and where that schema comes from decides whether the UI can ever
drift from the binary.

## Goals / Non-Goals

**Goals:** one declaration per field; a derived schema; secrets never readable back; field-scoped errors,
all reported at once; fail-fast at boot; layered sources behind an interface; a `config` subcommand.

**Non-Goals:** a UI or any network write path (the `Source` interface is the seam, not the feature); hot
reload; secret management; per-tenant config; the gateway and agent binaries (a follow-up reusing this
package).

## Decisions

### One declaration per field, and the schema is a projection of it

Each field is declared once — key, kind, default, description, validator — and both *reading* and
*describing* go through that declaration. There is no second list.

This is the decision the UI constraint forces. The alternative (a hand-written schema for the UI beside the
`os.Getenv` calls) fails in a specific, silent way: the form offers a field the binary never reads, an
operator sets it, nothing happens, and nobody finds out until an incident. Deriving the schema makes that
structurally impossible.

### Explicit field declarations, not struct-tag reflection

A reflection-and-struct-tags approach reads elegantly, and it moves the field's contract into a string
literal the compiler cannot check: a typo in a tag is a runtime surprise, and a validator expressed as tag
syntax is a small language to reimplement. Fields are therefore declared as values with real Go
functions for parsing and validation — more lines, checked by the compiler, and a validator is just code.

### Secrets are a KIND, not a naming convention

`KindSecret` is declared per field, so redaction is a property of the field rather than of whether someone
remembered to call the variable `*_TOKEN`. `Describe()` and the effective-config output both consult it, so
a new output path cannot forget: it has to go through the same accessor, which never returns a secret's
value at all.

### All errors, each scoped

`Validate()` returns a `FieldError` list, not a single error. Two reasons, both practical: an operator
fixing five variables should not need five boots, and a UI needs to attach each message to an input. A
single wrapped string can do neither.

### Layered sources with env on top

`Source` is an interface (`Lookup(key) (value string, ok bool)`), resolved in order: env → file → default.
Env on top preserves today's behaviour and the container idiom. A future DB source written by the UI slots
in below env — so an operator can still override a UI-set value on a single host without a database, which
is the property that matters during an incident.

### Backward compatibility is not negotiable

Every existing variable keeps its name, meaning and default. This change is about *how* values are declared
and validated, and a rename would turn a refactor into a migration for every deployment.

## Risks / Trade-offs

- **More lines than reflection** → accepted; the compiler checks them.
- **Fail-fast turns a previously-tolerated typo into a boot failure** → that is the point, and it is the
  stated acceptance criterion; the error names the field and the constraint.
- **This increment covers only the server** → the gateway keeps its current helpers until the follow-up;
  stated so partial coverage is not mistaken for the whole.
- **A file source without hot reload can look stale** → values are read at boot and the effective-config
  output states each value's origin, so "what is this process running with" is answerable.

## Migration Plan

No schema or wire change. Existing deployments keep working unchanged unless they were relying on a
malformed value silently falling back to a default — which now fails loudly at boot, and is the intended
behaviour change.

## Open Questions

- Whether the UI's write path should target the file source or a new DB source — deferred to PLAT-1, and
  deliberately not pre-empted here beyond making both possible.
