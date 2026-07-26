package config

import (
	"os"
	"strings"
	"sync/atomic"
)

// Scope decides WHERE a field's value comes from (PLAT-5b).
//
// This is the static/dynamic split serious platforms make explicit, and the reason the layered
// config-file model is refused: when several sources can supply the same operational setting, the console
// and the host can disagree with no signal, and "what is this deployment actually running" stops being
// answerable without logging into machines.
type Scope string

const (
	// ScopeBootstrap is what a process needs to START and REACH ITS DATABASE: the DSN, listen addresses,
	// TLS material, the config file itself, and where credentials live. Env/file only, restart to change.
	// It cannot live in the database — you need it to get to the database.
	//
	// Deliberately tiny. A test bounds the set, because the way this split dies is by accretion.
	ScopeBootstrap Scope = "bootstrap"
	// ScopeDynamic is everything else: thresholds, windows, intervals, retention, routing, connectors.
	// THE DATABASE IS ITS ONLY SOURCE, so a change applies to the whole deployment at once.
	ScopeDynamic Scope = "dynamic"
)

// BreakGlassEnv names the fields an operator is deliberately overriding from the environment, e.g.
// OPENSHIELD_BREAKGLASS=OPENSHIELD_CORRELATE_INTERVAL.
//
// The override then APPLIES AND IS REPORTED. That combination is the whole point: an operator needs a
// single-host override during an incident, and everyone else needs to be able to see that a host is not
// running what the console says. Visible beats convenient; silent is what this design refuses.
const BreakGlassEnv = "OPENSHIELD_BREAKGLASS"

func breakGlassKeys() map[string]bool {
	out := map[string]bool{}
	for _, k := range strings.Split(os.Getenv(BreakGlassEnv), ",") {
		if k = strings.TrimSpace(k); k != "" {
			out[k] = true
		}
	}
	return out
}

// Snapshot is an immutable set of stored settings at one revision. Immutable and swapped atomically, so a
// reader never observes a half-applied revision.
type Snapshot struct {
	Revision int64
	Values   map[string]string
}

// DBSource serves dynamic settings from the current snapshot. It is the ONLY source for a dynamic field.
type DBSource struct {
	snap atomic.Pointer[Snapshot]
}

// NewDBSource starts empty — every dynamic field then falls back to its declared default, which is what a
// deployment that has never written a setting should get.
func NewDBSource() *DBSource {
	d := &DBSource{}
	d.Set(&Snapshot{Values: map[string]string{}})
	return d
}

// Set swaps in a new snapshot atomically (live apply).
func (d *DBSource) Set(s *Snapshot) { d.snap.Store(s) }

// Snapshot returns the current one.
func (d *DBSource) Snapshot() *Snapshot { return d.snap.Load() }

// Revision reports which revision is in effect in THIS process — the answer to "has this host caught up".
func (d *DBSource) Revision() int64 {
	if s := d.snap.Load(); s != nil {
		return s.Revision
	}
	return 0
}

func (d *DBSource) Name() string { return "db" }

func (d *DBSource) Lookup(key string) (string, bool) {
	s := d.snap.Load()
	if s == nil {
		return "", false
	}
	v, ok := s.Values[key]
	if !ok || v == "" {
		return "", false
	}
	return v, true
}
