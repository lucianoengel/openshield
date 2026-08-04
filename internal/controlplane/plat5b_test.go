package controlplane_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/config"
	"github.com/lucianoengel/openshield/internal/controlplane"
)

// PLAT-5b: database-authoritative dynamic configuration with revisions and live apply.

func testResolver(db *config.DBSource) *config.Resolver {
	r := config.New([]config.Field{
		{Key: "D_INTERVAL", Scope: config.ScopeDynamic, Kind: config.KindDuration, Default: "1h",
			Description: "a dynamic duration"},
		{Key: "D_COUNT", Scope: config.ScopeDynamic, Kind: config.KindInt, Default: "3",
			Description: "a dynamic int"},
		{Key: "B_DSN", Scope: config.ScopeBootstrap, Kind: config.KindString, Default: "local",
			Description: "a bootstrap field"},
		{Key: "B_TOKEN", Scope: config.ScopeBootstrap, Kind: config.KindSecret, Description: "a credential"},
		{Key: "D_SECRET", Scope: config.ScopeDynamic, Kind: config.KindSecret, Description: "a credential"},
	}, config.EnvSource{})
	r.DB = db
	return r
}

// TestDynamicSettingsComeFromTheDatabase, and a change is a revision with an author and a diff.
func TestDynamicSettingsComeFromTheDatabase(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	db := config.NewDBSource()
	r := testResolver(db)
	ctx := context.Background()

	if got := r.Duration("D_INTERVAL"); got != time.Hour {
		t.Fatalf("unset dynamic field = %v, want its declared default", got)
	}
	rev, err := srv.ApplySettings(ctx, r, "cert:alice", "tighten correlation",
		map[string]string{"D_INTERVAL": "30s", "D_COUNT": "5"})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	snap, err := srv.SettingsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	db.Set(snap)
	if got := r.Duration("D_INTERVAL"); got != 30*time.Second {
		t.Errorf("D_INTERVAL = %v, want the stored 30s", got)
	}
	if got := r.Int("D_COUNT"); got != 5 {
		t.Errorf("D_COUNT = %d, want 5", got)
	}
	for _, ev := range r.Effective() {
		if ev.Key == "D_INTERVAL" && ev.Origin != "db" {
			t.Errorf("D_INTERVAL origin = %q, want db", ev.Origin)
		}
	}

	// The revision carries WHO and WHAT IT CHANGED FROM.
	revs, err := srv.Revisions(ctx, 10)
	if err != nil || len(revs) != 1 || revs[0].ID != rev {
		t.Fatalf("revisions = %+v err=%v", revs, err)
	}
	if revs[0].Author != "cert:alice" || revs[0].Note != "tighten correlation" {
		t.Errorf("revision = %+v, want the author and note recorded", revs[0])
	}
	byKey := map[string]controlplane.ConfigChange{}
	for _, c := range revs[0].Changes {
		byKey[c.Key] = c
	}
	if byKey["D_INTERVAL"].New != "30s" || byKey["D_INTERVAL"].Old != "" {
		t.Errorf("diff = %+v — 'who widened the window' needs to say what it was widened FROM", byKey)
	}
}

// TestAChangeIsValidatedAndRefusedInFull.
//
// Mutation: apply the valid keys and skip the invalid one → FAILS. Partial application would leave a
// deployment in a state no operator chose.
func TestAChangeIsValidatedAndRefusedInFull(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	r := testResolver(config.NewDBSource())
	ctx := context.Background()

	if _, err := srv.ApplySettings(ctx, r, "cert:alice", "",
		map[string]string{"D_COUNT": "7", "D_INTERVAL": "half an hour"}); err == nil {
		t.Fatal("an invalid duration was accepted")
	}
	if n := countRows(t, pool, `SELECT count(*) FROM config_settings`); n != 0 {
		t.Errorf("%d setting(s) applied from a REFUSED change — one bad key must refuse the whole "+
			"revision, or a deployment lands in a state nobody chose", n)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM config_revisions`); n != 0 {
		t.Errorf("%d revision(s) created for a refused change", n)
	}

	// An unknown key would be a value nobody reads.
	if _, err := srv.ApplySettings(ctx, r, "cert:alice", "",
		map[string]string{"D_NOT_A_FIELD": "x"}); !errors.Is(err, controlplane.ErrUnknownSetting) {
		t.Errorf("unknown key error = %v, want ErrUnknownSetting", err)
	}
	// A bootstrap field must reach the process BEFORE the database does.
	if _, err := srv.ApplySettings(ctx, r, "cert:alice", "",
		map[string]string{"B_DSN": "postgres://x"}); !errors.Is(err, controlplane.ErrNotDynamic) {
		t.Errorf("bootstrap write error = %v, want ErrNotDynamic", err)
	}
}

// TestSecretsAreNeverStored — a dump of the config database must not be a dump of the credentials.
//
// Mutation: allow a secret through the write path → FAILS.
func TestSecretsAreNeverStored(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	r := testResolver(config.NewDBSource())
	ctx := context.Background()

	for _, key := range []string{"D_SECRET", "B_TOKEN"} {
		_, err := srv.ApplySettings(ctx, r, "cert:alice", "", map[string]string{key: "s3cret-value"})
		if err == nil {
			t.Errorf("%s was stored — a backup of this database is now a backup of the deployment's "+
				"credentials", key)
		}
		if key == "D_SECRET" && !errors.Is(err, controlplane.ErrSecretNotStorable) {
			t.Errorf("error = %v, want ErrSecretNotStorable", err)
		}
	}
	if n := countRows(t, pool, `SELECT count(*) FROM config_settings`); n != 0 {
		t.Errorf("%d row(s) stored for a secret", n)
	}
	// And the refusal itself must not echo the value back.
	_, err := srv.ApplySettings(ctx, r, "cert:alice", "", map[string]string{"D_SECRET": "s3cret-value"})
	if err != nil && strings.Contains(err.Error(), "s3cret-value") {
		t.Errorf("the refusal leaked the secret value: %v", err)
	}
}

// TestEnvDoesNotSilentlyOverrideADynamicSetting is the trap this ticket exists to refuse: a console
// showing one value while a host runs another, with no signal.
//
// Mutation: let env win for a dynamic field → FAILS.
func TestEnvDoesNotSilentlyOverrideADynamicSetting(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	db := config.NewDBSource()
	r := testResolver(db)
	ctx := context.Background()

	if _, err := srv.ApplySettings(ctx, r, "cert:alice", "",
		map[string]string{"D_INTERVAL": "30s"}); err != nil {
		t.Fatal(err)
	}
	snap, _ := srv.SettingsSnapshot(ctx)
	db.Set(snap)

	t.Setenv("D_INTERVAL", "99h")
	if got := r.Duration("D_INTERVAL"); got != 30*time.Second {
		t.Errorf("D_INTERVAL = %v, want the STORED 30s — an environment value that silently shadows a "+
			"stored one is how a console and a host come to disagree with no signal", got)
	}
	ignored := r.IgnoredOverrides()
	if len(ignored) != 1 || ignored[0] != "D_INTERVAL" {
		t.Errorf("ignored overrides = %v, want [D_INTERVAL] — the operator who set it believes it is "+
			"doing something", ignored)
	}

	// BREAK-GLASS: explicit, applied, AND reported.
	t.Setenv(config.BreakGlassEnv, "D_INTERVAL")
	if got := r.Duration("D_INTERVAL"); got != 99*time.Hour {
		t.Errorf("break-glass did not apply: %v", got)
	}
	var origin string
	for _, ev := range r.Effective() {
		if ev.Key == "D_INTERVAL" {
			origin = ev.Origin
		}
	}
	if !strings.Contains(origin, "break-glass") {
		t.Errorf("origin = %q — an override that is not reported is the silent disagreement this design "+
			"refuses", origin)
	}
	if len(r.IgnoredOverrides()) != 0 {
		t.Error("a break-glass field is still listed as ignored")
	}
}

// TestRollbackRestoresValuesAsANewRevision — history is never deleted.
//
// Mutation: implement rollback by deleting revisions → FAILS.
func TestRollbackRestoresValuesAsANewRevision(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	db := config.NewDBSource()
	r := testResolver(db)
	ctx := context.Background()

	first, err := srv.ApplySettings(ctx, r, "cert:alice", "initial", map[string]string{"D_COUNT": "3"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.ApplySettings(ctx, r, "cert:bob", "widen", map[string]string{"D_COUNT": "99"}); err != nil {
		t.Fatal(err)
	}
	back, err := srv.RollbackTo(ctx, r, first, "cert:carol")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	snap, _ := srv.SettingsSnapshot(ctx)
	db.Set(snap)
	if got := r.Int("D_COUNT"); got != 3 {
		t.Errorf("D_COUNT = %d after rollback, want 3", got)
	}
	revs, err := srv.Revisions(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 3 {
		t.Fatalf("%d revisions after a rollback, want 3 — an audit trail you can rewind by ERASING is "+
			"not one", len(revs))
	}
	if revs[0].ID != back || revs[0].Author != "cert:carol" {
		t.Errorf("the rollback is not recorded as its own attributed revision: %+v", revs[0])
	}
	if !strings.Contains(revs[0].Note, "rollback") || revs[0].Changes[0].Old != "99" {
		t.Errorf("the rollback revision does not record what it undid: %+v", revs[0])
	}
}

// TestSavedChangeAppliesWithoutARestart is the property that separates this from a config file.
//
// Mutation: have the loop capture its interval/rule at start instead of reading per tick → FAILS.
func TestSavedChangeAppliesWithoutARestart(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	db := config.NewDBSource()
	r := testResolver(db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The watcher is what makes a saved change reach a running process.
	go srv.WatchSettings(ctx, db, 20*time.Millisecond)

	if got := r.Int("D_COUNT"); got != 3 {
		t.Fatalf("D_COUNT starts at %d, want the default 3", got)
	}
	if _, err := srv.ApplySettings(ctx, r, "cert:alice", "live", map[string]string{"D_COUNT": "11"}); err != nil {
		t.Fatal(err)
	}
	// No restart, no re-read by the test: the running process picks it up.
	waitFor(t, func() bool { return r.Int("D_COUNT") == 11 })

	// And a RUNNING LOOP uses the new value, rather than one captured when it started.
	var seen []int
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	loopCtx, stop := context.WithCancel(ctx)
	defer stop()
	go retainDynamic(loopCtx, func() time.Duration { return 10 * time.Millisecond }, func() {
		<-mu
		seen = append(seen, r.Int("D_COUNT"))
		mu <- struct{}{}
	})
	waitFor(t, func() bool {
		<-mu
		defer func() { mu <- struct{}{} }()
		return len(seen) >= 2
	})
	if _, err := srv.ApplySettings(ctx, r, "cert:alice", "again", map[string]string{"D_COUNT": "22"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		<-mu
		defer func() { mu <- struct{}{} }()
		for _, v := range seen {
			if v == 22 {
				return true
			}
		}
		return false
	})
}

// retainDynamic mirrors retain.DynamicLoop's shape for the test without importing it, so the assertion is
// about the RESOLVER being live rather than about that helper.
func retainDynamic(ctx context.Context, every func() time.Duration, fn func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every()):
			fn()
		}
	}
}
