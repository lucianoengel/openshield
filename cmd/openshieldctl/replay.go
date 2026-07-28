package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/lucianoengel/openshield/internal/cli"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

// `openshieldctl replay` — the reproducible half of the platform's claim, finally executable.
//
// `core.Replay` and `core.DecisionsEquivalent` were written, documented and unit-tested with no caller:
// the ledger could always be VERIFIED (it was not edited) and never REPLAYED (the record follows from
// the inputs and the policy). This is the command that asks the second question.
//
// IT REPLAYS AGAINST THE POLICY CONFIGURED NOW, not the one named on the recorded entry. The recorded
// policy id says what evaluated it THEN; the point of the command is what happens NOW — which is what
// makes it useful as a gate on a policy change ("would this still produce last quarter's decisions?").
// When the two differ the report names both, so a divergence explained by "you are running a different
// policy" does not read as a regression.
func replayCmd(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	eventPath := fs.String("event", "", "file holding the event to replay (protojson)")
	dsn := fs.String("dsn", os.Getenv("OPENSHIELD_DSN"), "Postgres DSN")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUnavailable
	}
	if *eventPath == "" {
		fmt.Fprintln(os.Stderr, "openshieldctl: --event is required; the ledger stores no content, so "+
			"the event to replay has to come from you")
		return cli.ExitUnavailable
	}
	if *dsn == "" {
		*dsn = defaultDSN
	}

	raw, err := os.ReadFile(*eventPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: reading the event: %v\n", err)
		return cli.ExitUnavailable
	}
	var ev corev1.Event
	if err := protojson.Unmarshal(raw, &ev); err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: %s is not a readable Event: %v\n", *eventPath, err)
		return cli.ExitUnavailable
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	r, err := postgres.OpenForVerify(ctx, *dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
		return cli.ExitUnavailable
	}
	defer r.Close()

	// THE SAME SELECTOR THE ENGINE USES, from the same OPENSHIELD_POLICY_* environment — not a
	// hand-composed policy here.
	//
	// The first version of this called policy.NewComposite directly with an empty pack list, and a
	// decision the engine had just written FAILED TO REPLAY: the engine stamps `openshield.default`
	// and composing nothing stamps `openshield.composite`, so identical rules carried different policy
	// identities and replay compared them. SelectFromEnv already resolves that — with no packs and no
	// custom module it returns the plain default — and reusing it means the CLI cannot drift from what
	// the engine loaded, which is the only way this command's answer means anything.
	pol, err := policy.SelectFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: loading the policy: %v\n", err)
		return cli.ExitUnavailable
	}

	// NO CLASSIFIER STAGE, and this is a limit rather than an oversight: openshieldctl is READ-ONLY and
	// holds no worker, so it replays the POLICY over the event's metadata. A decision that turned on
	// content classification will therefore diverge here for a reason that is not a policy change —
	// which the report already warns about, and which the registry below makes explicit by carrying
	// only the policy stage.
	var reg core.Registry
	reg.Register(pol)
	disp := core.NewDispatcher(&reg, 30*time.Second)

	return cli.Replay(ctx, os.Stdout, r, disp, &ev)
}
