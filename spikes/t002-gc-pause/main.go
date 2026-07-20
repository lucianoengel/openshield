// Command t002-gc-pause measures whether Go's garbage collector introduces
// latency that would make it unsuitable for the fanotify permission-response
// path (decision D19, ticket T-002).
//
// # Why this matters
//
// fanotify permission events (FAN_OPEN_PERM) block the calling process in the
// kernel until userspace writes a verdict. The process sits in
// TASK_UNINTERRUPTIBLE while it waits. If the responder stalls, real processes
// stall with it — and there are documented production incidents where a slow
// fanotify listener hung an entire machine.
//
// Decision D8 chose Go for the whole project. Review challenged that for this
// one component: GC pauses and scheduler jitter sit directly inside a live
// permission window. This spike measures the actual distribution rather than
// arguing about it.
//
// # What this measures, and what it does not
//
// MEASURES: the Go-side latency from "an event is ready to handle" to "a
// verdict has been produced", under varying allocation pressure — plus the
// GC pause distribution reported by runtime/metrics.
//
// DOES NOT MEASURE: kernel-side fanotify overhead, syscall cost, or IPC to the
// classifier worker. Those are real but they are not what D19 is about, and
// FAN_CLASS_CONTENT needs CAP_SYS_ADMIN which the dev sandbox lacks. The
// question here is narrow and answerable: does the Go runtime itself introduce
// tail latency large enough to matter?
//
// This is throwaway spike code. It is kept in the repository because it is the
// evidence for a decision, not because it is part of the product.
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"runtime/metrics"
	"sort"
	"time"
)

// verdictWork approximates what the privileged responder actually does per
// event: look at a path, consult a compiled policy, allocate a small record,
// and answer. Deliberately modest — under D13 the privileged process never
// parses file content, so this is bookkeeping, not classification.
func verdictWork(path string, r *rand.Rand) bool {
	rec := make([]byte, 128+r.Intn(256))
	for i := range rec {
		rec[i] = path[i%len(path)]
	}
	h := 0
	for _, b := range rec {
		h = h*31 + int(b)
	}
	return h%1000 != 0
}

// pressure simulates the rest of the agent allocating while the responder runs:
// event structs, telemetry batches, queue buffers. This is what forces GC to
// run during the measurement window.
func pressure(stop <-chan struct{}, mbPerSec int) {
	if mbPerSec <= 0 {
		return
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	chunk := mbPerSec * 1024 * 1024 / 100
	var sink [][]byte
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			b := make([]byte, chunk)
			b[0] = 1
			sink = append(sink, b)
			// Retain a bounded working set so the heap stays live rather than
			// being trivially collectable — closer to a real agent's profile.
			if len(sink) > 40 {
				sink = sink[len(sink)-40:]
			}
		}
	}
}

type result struct {
	name                     string
	eventsPerSec             int
	pressureMBs              int
	n                        int
	p50, p99, p999, max      time.Duration
	gcCount                  uint64
	gcPauseP99, gcPauseMax   time.Duration
}

func gcPauseSnapshot() (count uint64, p99, max time.Duration) {
	s := []metrics.Sample{{Name: "/gc/pauses:seconds"}}
	metrics.Read(s)
	h := s[0].Value.Float64Histogram()
	var total uint64
	for _, c := range h.Counts {
		total += c
	}
	if total == 0 {
		return 0, 0, 0
	}
	// NOTE: these are histogram bucket upper bounds, so they overestimate.
	// A reported 300µs may be a pause anywhere in that bucket. Good enough to
	// answer "is this milliseconds or microseconds", which is the question.
	target := uint64(float64(total) * 0.99)
	var seen uint64
	for i, c := range h.Counts {
		seen += c
		if seen >= target && p99 == 0 {
			p99 = time.Duration(h.Buckets[i+1] * float64(time.Second))
		}
		if c > 0 {
			max = time.Duration(h.Buckets[i+1] * float64(time.Second))
		}
	}
	return total, p99, max
}

func run(name string, eventsPerSec, pressureMBs int, dur time.Duration) result {
	stop := make(chan struct{})
	go pressure(stop, pressureMBs)
	defer close(stop)

	// Let pressure establish a steady-state heap before measuring.
	time.Sleep(500 * time.Millisecond)
	beforeCount, _, _ := gcPauseSnapshot()

	r := rand.New(rand.NewSource(1))
	interval := time.Second / time.Duration(eventsPerSec)
	latencies := make([]time.Duration, 0, int(dur/interval)+16)
	paths := []string{
		"/home/user/Documents/report.docx",
		"/home/user/.cache/thumbnails/x.png",
		"/var/log/syslog",
		"/home/user/Downloads/customers.csv",
	}

	// The producer stands in for the kernel handing us permission events. It
	// timestamps at the moment of hand-off, NOT at the intended tick — an
	// earlier version of this spike measured from the intended tick, which
	// meant it was measuring time.Sleep overshoot (~500µs) and GC was
	// invisible underneath it. The giveaway was that the zero-GC scenario
	// posted the worst maximum.
	type event struct {
		path string
		sent time.Time
	}
	ch := make(chan event, 1024)
	done := make(chan struct{})
	go func() {
		defer close(ch)
		deadline := time.Now().Add(dur)
		next := time.Now()
		for time.Now().Before(deadline) {
			next = next.Add(interval)
			if d := time.Until(next); d > 0 {
				time.Sleep(d)
			}
			select {
			case ch <- event{paths[r.Intn(len(paths))], time.Now()}:
			case <-done:
				return
			}
		}
	}()

	// The responder is the component under test: it must produce a verdict
	// promptly, because a real caller is blocked in TASK_UNINTERRUPTIBLE until
	// it does. Latency here is queue wait + scheduling + GC interference +
	// the work itself.
	for ev := range ch {
		verdictWork(ev.path, r)
		latencies = append(latencies, time.Since(ev.sent))
	}
	close(done)

	afterCount, gcP99, gcMax := gcPauseSnapshot()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pct := func(p float64) time.Duration {
		if len(latencies) == 0 {
			return 0
		}
		i := int(float64(len(latencies)) * p)
		if i >= len(latencies) {
			i = len(latencies) - 1
		}
		return latencies[i]
	}
	return result{
		name: name, eventsPerSec: eventsPerSec, pressureMBs: pressureMBs,
		n:   len(latencies),
		p50: pct(0.50), p99: pct(0.99), p999: pct(0.999),
		max:        latencies[len(latencies)-1],
		gcCount:    afterCount - beforeCount,
		gcPauseP99: gcP99, gcPauseMax: gcMax,
	}
}

func main() {
	dur := flag.Duration("d", 10*time.Second, "duration per scenario")
	flag.Parse()

	fmt.Printf("go=%s GOMAXPROCS=%d GOGC=%s GOMEMLIMIT=%s\n\n",
		runtime.Version(), runtime.GOMAXPROCS(0),
		orDefault(os.Getenv("GOGC"), "100"), orDefault(os.Getenv("GOMEMLIMIT"), "unset"))

	scenarios := []struct {
		name         string
		eventsPerSec int
		pressureMBs  int
	}{
		{"idle (no pressure)", 500, 0},
		{"moderate load", 500, 64},
		{"heavy load", 500, 256},
		{"heavy load, high event rate", 5000, 256},
	}

	results := make([]result, 0, len(scenarios))
	for _, s := range scenarios {
		results = append(results, run(s.name, s.eventsPerSec, s.pressureMBs, *dur))
	}

	fmt.Printf("%-30s %7s %8s %9s %9s %9s %9s %6s %9s %9s\n",
		"scenario", "ev/s", "alloc", "n", "p50", "p99", "p99.9", "max", "GCs", "gcPause99")
	for _, r := range results {
		fmt.Printf("%-30s %7d %6dMB %9d %9s %9s %9s %6s %9d %9s\n",
			r.name, r.eventsPerSec, r.pressureMBs, r.n,
			round(r.p50), round(r.p99), round(r.p999), round(r.max),
			r.gcCount, round(r.gcPauseP99))
	}

	worst := time.Duration(0)
	for _, r := range results {
		if r.max > worst {
			worst = r.max
		}
	}
	fmt.Printf("\nworst-case response latency across all scenarios: %s\n", round(worst))
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func round(d time.Duration) time.Duration {
	switch {
	case d > time.Millisecond:
		return d.Round(10 * time.Microsecond)
	case d > time.Microsecond:
		return d.Round(100 * time.Nanosecond)
	default:
		return d
	}
}
