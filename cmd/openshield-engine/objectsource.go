package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/lucianoengel/openshield/internal/clipboard"
	"github.com/lucianoengel/openshield/internal/connectors/objectstore"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
)

// THE DISCOVERY SOURCE (DSPM-1): data AT REST, as opposed to everything else this engine watches.
//
// Every other source here is an interposition point — a file being written, a paste, a print job, an SMTP
// session. This one goes looking: it enumerates an S3-compatible bucket on an interval and reads a bounded
// prefix of each object, so the product can answer "where is my sensitive data" rather than only "who
// touched it".
//
// OFF UNLESS CONFIGURED, and it refuses to start half-configured. A discovery sweep that runs against the
// wrong store, or with no credentials, produces "nothing found" — and that is the one output of this feature
// nobody re-checks. Refusing to start is the only safe failure.

// objectSweepSource starts the periodic discovery sweep. It returns false when the connector is not
// configured, so the caller can stay quiet rather than logging an absence as a problem.
func objectSweepSource(ctx context.Context, eng contentResolverHost, events chan<- *corev1.Event,
	log *slog.Logger) (func(), bool) {
	endpoint := strings.TrimSpace(os.Getenv("OPENSHIELD_OBJECT_ENDPOINT"))
	bucket := strings.TrimSpace(os.Getenv("OPENSHIELD_OBJECT_BUCKET"))
	if endpoint == "" || bucket == "" {
		return nil, false
	}

	cfg := objectstore.Config{
		Endpoint: endpoint,
		Bucket:   bucket,
		Region:   env("OPENSHIELD_OBJECT_REGION", "us-east-1"),
		Prefix:   os.Getenv("OPENSHIELD_OBJECT_PREFIX"),
		Creds: objectstore.Credentials{
			AccessKeyID:     os.Getenv("OPENSHIELD_OBJECT_ACCESS_KEY"),
			SecretAccessKey: os.Getenv("OPENSHIELD_OBJECT_SECRET_KEY"),
		},
		MaxObjects:     envInt("OPENSHIELD_OBJECT_MAX_OBJECTS", objectstore.DefaultMaxObjects),
		MaxObjectBytes: int64(envInt("OPENSHIELD_OBJECT_MAX_BYTES", objectstore.DefaultMaxObjectBytes)),
	}
	client, err := objectstore.New(cfg)
	if err != nil {
		// FATAL, not a warning. A misconfigured sweep reports an empty bucket, which is indistinguishable
		// from a clean one and is the answer nobody goes back to verify.
		fatal(log, "object discovery", err)
	}

	// CHAINED into the content resolver rather than installed over it — the resolver holds exactly ONE
	// function, so an assignment here would silently disable clipboard, print or SMTP classification for
	// anyone who enables both. Same shape as the SMTP source, for the same reason.
	store := clipboard.NewContentStore(nil)
	prev := eng.ContentResolver()
	eng.SetContentResolver(func(ev *corev1.Event) []byte {
		if b := store.Resolve(ev.GetEventId()); len(b) > 0 {
			return b
		}
		if prev != nil {
			return prev(ev)
		}
		return nil
	})

	interval := envDuration("OPENSHIELD_OBJECT_SWEEP_INTERVAL", time.Hour)
	log.Info("engine: object discovery ACTIVE (DSPM-1)",
		slog.String("bucket", bucket),
		slog.String("interval", interval.String()),
		slog.Int("max_objects", cfg.MaxObjects),
		slog.Int64("max_object_bytes", cfg.MaxObjectBytes),
		slog.String("limits", "a sweep reads a bounded PREFIX of a bounded NUMBER of objects — content past "+
			"either ceiling is not examined, and the per-sweep report says how much was skipped"))

	return func() {
		// SWEEP IMMEDIATELY, then on the interval. Waiting a full interval before the first sweep means a
		// freshly configured deployment reports nothing for an hour and looks broken.
		for {
			sweepOnce(ctx, client, store, events, log)
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
			}
		}
	}, true
}

// sweepOnce runs one enumeration and feeds every discovered object into the pipeline.
func sweepOnce(ctx context.Context, client *objectstore.Client, store *clipboard.ContentStore,
	events chan<- *corev1.Event, log *slog.Logger) {
	sw := objectstore.NewSweeper(client, store.Put)
	for {
		ev, err := sw.Next(ctx)
		if err != nil {
			// The sweep is abandoned, LOUDLY. A discovery run that failed halfway and said nothing would
			// leave a partial result looking like a complete one.
			log.Error("object discovery sweep failed — its result is PARTIAL and must not be read as a "+
				"clean bucket", slog.String("err", err.Error()), slog.String("report", sw.Report().String()))
			return
		}
		if ev == nil {
			break
		}
		select {
		case events <- ev:
		case <-ctx.Done():
			return
		}
	}
	// COVERAGE IS REPORTED EVERY SWEEP, not only when something was skipped. An operator reading the log
	// should be able to see what a clean result actually covered without inferring it from silence.
	log.Info("object discovery sweep complete", slog.String("report", sw.Report().String()))
}

// contentResolverHost is the slice of the engine this source needs, named so the dependency is visible
// rather than the whole engine being passed around.
type contentResolverHost interface {
	ContentResolver() engine.ContentResolver
	SetContentResolver(engine.ContentResolver)
}
