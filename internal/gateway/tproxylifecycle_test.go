package gateway

import (
	"context"
	"errors"
	"testing"
)

// TestRuleLifecycleRemovesOnServerStop: when Serve returns (an error, ctx still live), the rules are removed
// exactly once — the rules must not outlive the server. This is the core inc-4b invariant.
//
// Mutation (bind remove to ctx.Done() instead of the serve return): a serve that returns before ctx cancel
// leaves remove uncalled → this FAILs.
func TestRuleLifecycleRemovesOnServerStop(t *testing.T) {
	removes := 0
	runTProxyWithRules(context.Background(),
		func(context.Context) error { return errors.New("listener died") }, // serve returns early
		func() error { return nil },                                        // install ok
		func() { removes++ },
		nil)
	if removes != 1 {
		t.Fatalf("remove called %d times on an unexpected server stop, want exactly 1 (rules must not outlive the server)", removes)
	}
}

// TestRuleLifecycleNoRemoveWhenInstallFailed: if install failed, remove must NOT run — never delete rules we
// did not add (the operator may own them out of band).
func TestRuleLifecycleNoRemoveWhenInstallFailed(t *testing.T) {
	removes := 0
	runTProxyWithRules(context.Background(),
		func(context.Context) error { return nil },
		func() error { return errors.New("install failed") },
		func() { removes++ },
		nil)
	if removes != 0 {
		t.Fatalf("remove called %d times after install failed, want 0 (never delete rules we did not add)", removes)
	}
}

// TestRuleLifecycleRemovesOnCtxCancel: the D237 clean-shutdown path still holds — a serve that returns
// because ctx was cancelled also removes the rules.
func TestRuleLifecycleRemovesOnCtxCancel(t *testing.T) {
	removes := 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runTProxyWithRules(ctx,
		func(c context.Context) error { return c.Err() }, // serve returns ctx.Err()
		func() error { return nil },
		func() { removes++ },
		nil)
	if removes != 1 {
		t.Fatalf("remove called %d times on ctx-cancel shutdown, want 1", removes)
	}
}
