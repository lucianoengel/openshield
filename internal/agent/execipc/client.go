package execipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// Client is the PRIVILEGED side of the exec-verdict transport: a watchdog.Evaluator that asks the engine
// for a verdict (HIPS-3 increment 2a).
//
// Its contract is narrow and absolute: NEVER BLOCK, and NEVER GUESS.
//
// It deliberately implements no budget and no fail-open of its own. watchdog.Handle already races
// evaluation against the per-event budget and fails open — with a high-severity audit — on both timeout
// and evaluator error, and it writes the kernel answer BEFORE auditing so a slow ledger cannot become a
// hung host. A second timeout mechanism here would be a second source of truth about when to give up, and
// the one that disagreed under load would be the one that wedged a machine. So every failure this client
// can have is returned as an ERROR, and the watchdog turns it into an audited allow.
//
// Fail-open is a load-bearing SAFETY property here, not a bug: a privileged gate that failed closed when
// its evaluator died would remove the host's ability to run programs (D17/D73, the same discipline as the
// network bypass watchdog and the egress fail-open).
type Client struct {
	// Socket is the unix socket the engine listens on.
	Socket string
	// Timeout bounds one round trip. It MUST be shorter than the watchdog budget so the transport is
	// never the thing that exhausts the permission window.
	Timeout time.Duration
	// CacheTTL is how long a path's verdict may answer a repeated exec of the same path. A fork loop over
	// one binary collapses to one pipeline evaluation. The honest cost is staleness up to the TTL.
	CacheTTL time.Duration
	// BreakerThreshold is how many CONSECUTIVE failures for a path trip its breaker; BreakerCooldown is
	// how long the breaker then fails open WITHOUT touching the socket. Without this, a dead engine turns
	// every exec into a full connect-and-time-out cycle and the fail-open path becomes the bottleneck.
	BreakerThreshold int
	BreakerCooldown  time.Duration
	// MaxInFlight bounds concurrent round trips; overflow fails open immediately rather than queueing.
	// An unbounded queue under a fork storm is a memory-exhaustion bug in a privileged process.
	MaxInFlight int

	// Logf is optional; nil discards. The privileged binary has no slog (encoding/json is banned), so
	// this is a plain printf seam.
	Logf func(format string, a ...any)

	initOnce sync.Once

	// connLock is a DEADLINE-AWARE lock (capacity-1 channel), not a sync.Mutex. The protocol is
	// serialized — one outstanding request per connection — so a second exec must wait for the first.
	// With a plain mutex that wait is UNBOUNDED from the waiter's point of view: under a fork storm the
	// Nth exec would sit on the mutex for up to N×Timeout, inside a fanotify permission window. A waiter
	// that cannot take the lock before ITS OWN deadline fails open instead, which is the whole point of
	// bounding this surface.
	connLock chan struct{}
	conn     net.Conn
	nextID   uint64

	cacheMu sync.Mutex
	cache   map[string]cacheEntry

	breakerMu sync.Mutex
	breakers  map[string]*breaker

	sem chan struct{}

	// Counters, exported for tests and for an operator to see that the safety valves are firing.
	FailOpens    atomic64
	CacheHits    atomic64
	BreakerTrips atomic64
	Overflows    atomic64
}

type cacheEntry struct {
	verdict watchdog.Verdict
	expires time.Time
}

type breaker struct {
	consecutive int
	openUntil   time.Time
}

// Defaults chosen to sit comfortably inside a typical permission budget.
const (
	DefaultTimeout          = 200 * time.Millisecond
	DefaultCacheTTL         = time.Second
	DefaultBreakerThreshold = 3
	DefaultBreakerCooldown  = 5 * time.Second
	DefaultMaxInFlight      = 16
)

// NewClient returns a Client with defaults filled in.
//
// Configure any field BEFORE the first Evaluate: the internals derived from configuration (above all the
// in-flight semaphore, whose capacity is MaxInFlight) are built lazily on first use, so a later change to
// MaxInFlight would be silently ignored. Building them eagerly here was the first version of this code and
// exactly that trap — a test that set MaxInFlight after NewClient got the default bound and a confusing
// failure instead of the behavior it asked for.
func NewClient(socket string) *Client {
	return &Client{
		Socket:           socket,
		Timeout:          DefaultTimeout,
		CacheTTL:         DefaultCacheTTL,
		BreakerThreshold: DefaultBreakerThreshold,
		BreakerCooldown:  DefaultBreakerCooldown,
		MaxInFlight:      DefaultMaxInFlight,
	}
}

func (c *Client) init() {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.BreakerThreshold <= 0 {
		c.BreakerThreshold = DefaultBreakerThreshold
	}
	if c.BreakerCooldown <= 0 {
		c.BreakerCooldown = DefaultBreakerCooldown
	}
	if c.MaxInFlight <= 0 {
		c.MaxInFlight = DefaultMaxInFlight
	}
	if c.cache == nil {
		c.cache = map[string]cacheEntry{}
	}
	if c.breakers == nil {
		c.breakers = map[string]*breaker{}
	}
	if c.sem == nil {
		c.sem = make(chan struct{}, c.MaxInFlight)
	}
	if c.connLock == nil {
		c.connLock = make(chan struct{}, 1)
	}
}

// ErrBreakerOpen / ErrOverflow are the two LOCAL fail-open reasons — the gate gave up without an IPC
// attempt. They are errors like any other, so the watchdog's audit records them; they are distinguished
// so an operator can tell "the engine is down" from "the engine is slow".
var (
	ErrBreakerOpen = errors.New("execipc: circuit breaker open for this path (failing open without a call)")
	ErrOverflow    = errors.New("execipc: too many in-flight verdict requests (failing open)")
	// ErrBusy means the connection was occupied for this request's whole budget. Distinct from ErrOverflow
	// (which is refused before dialing) so an operator can tell contention from saturation.
	ErrBusy = errors.New("execipc: verdict connection busy for the whole budget (failing open)")
)

// Evaluate implements watchdog.Evaluator.
func (c *Client) Evaluate(ctx context.Context, e watchdog.PermissionEvent) (watchdog.Verdict, error) {
	c.once()
	// A cached verdict for this path answers a fork storm without a syscall.
	if v, ok := c.cached(e.Path); ok {
		c.CacheHits.add(1)
		return v, nil
	}
	// A tripped breaker fails open WITHOUT dialing — the point is to stop spending the permission budget
	// on a call already known to fail.
	if c.breakerOpen(e.Path) {
		c.FailOpens.add(1)
		return watchdog.VerdictAllow, ErrBreakerOpen
	}
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	default:
		c.Overflows.add(1)
		c.FailOpens.add(1)
		return watchdog.VerdictAllow, ErrOverflow
	}

	// The deadline is computed HERE, at entry, so a request that waits for the connection spends its own
	// budget rather than starting a fresh one once it finally gets the lock.
	deadline := time.Now().Add(c.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d // never outlive the caller's budget
	}
	v, err := c.roundTrip(deadline, e)
	if err != nil {
		c.recordFailure(e.Path)
		c.FailOpens.add(1)
		// VerdictAllow is returned alongside the error for belt-and-braces: watchdog.Handle fails open on
		// a non-nil error regardless of the verdict, but a caller that ignored the error must still not
		// read a block out of a failed evaluation.
		return watchdog.VerdictAllow, err
	}
	c.recordSuccess(e.Path)
	c.store(e.Path, v)
	return v, nil
}

// roundTrip sends one request and reads its answer, serialized so the stream carries exactly one
// outstanding request at a time. It never waits past the caller's deadline.
func (c *Client) roundTrip(deadline time.Time, e watchdog.PermissionEvent) (watchdog.Verdict, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case c.connLock <- struct{}{}:
		defer func() { <-c.connLock }()
	case <-timer.C:
		return watchdog.VerdictAllow, ErrBusy
	}

	conn, err := c.connect(deadline)
	if err != nil {
		return watchdog.VerdictAllow, err
	}
	c.nextID++
	id := c.nextID

	if err := conn.SetDeadline(deadline); err != nil {
		c.dropLocked()
		return watchdog.VerdictAllow, err
	}
	if err := WriteRequest(conn, Request{ID: id, PID: e.PID, Path: e.Path}); err != nil {
		c.dropLocked() // a partial write desynchronizes the stream — never reuse it
		return watchdog.VerdictAllow, fmt.Errorf("execipc: write: %w", err)
	}
	resp, err := ReadResponse(conn)
	if err != nil {
		c.dropLocked()
		return watchdog.VerdictAllow, fmt.Errorf("execipc: read: %w", err)
	}
	if resp.ID != id {
		// The worst available failure of an inline gate is answering execution A with execution B's
		// verdict: silently wrong in BOTH directions, and invisible in the audit trail. A stream that has
		// desynchronized cannot be trusted to resynchronize itself, so the connection dies with the error.
		c.dropLocked()
		return watchdog.VerdictAllow, fmt.Errorf("%w: got %d, want %d", ErrIDMismatch, resp.ID, id)
	}
	if resp.Verdict == VerdictDeny {
		return watchdog.VerdictBlock, nil
	}
	return watchdog.VerdictAllow, nil
}

// connect returns the live connection, dialing lazily. One socket, no pool: a pool would add concurrency
// the protocol does not need and multiply the desynchronization risk above by its size.
func (c *Client) connect(deadline time.Time) (net.Conn, error) {
	if c.conn != nil {
		return c.conn, nil
	}
	d := net.Dialer{Deadline: deadline}
	conn, err := d.Dial("unix", c.Socket)
	if err != nil {
		return nil, fmt.Errorf("execipc: dial %s: %w", c.Socket, err)
	}
	c.conn = conn
	return conn, nil
}

// dropLocked closes and forgets the connection so the next event redials. This is what makes an engine
// restart cost a fail-open or two and then recover by itself, with no stuck error state.
func (c *Client) dropLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// Close releases the connection.
func (c *Client) Close() error {
	c.once()
	c.connLock <- struct{}{}
	defer func() { <-c.connLock }()
	c.dropLocked()
	return nil
}

func (c *Client) cached(path string) (watchdog.Verdict, bool) {
	if c.CacheTTL <= 0 || path == "" {
		return watchdog.VerdictAllow, false
	}
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	e, ok := c.cache[path]
	if !ok || time.Now().After(e.expires) {
		return watchdog.VerdictAllow, false
	}
	return e.verdict, true
}

func (c *Client) store(path string, v watchdog.Verdict) {
	if c.CacheTTL <= 0 || path == "" {
		return
	}
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	// Bounded so a directory of distinct binaries cannot grow the cache without limit; on overflow the
	// map is cleared rather than evicting cleverly (this is a 1-second TTL, not a database).
	if len(c.cache) > 4096 {
		c.cache = map[string]cacheEntry{}
	}
	c.cache[path] = cacheEntry{verdict: v, expires: time.Now().Add(c.CacheTTL)}
}

func (c *Client) breakerOpen(path string) bool {
	c.breakerMu.Lock()
	defer c.breakerMu.Unlock()
	b, ok := c.breakers[path]
	if !ok {
		return false
	}
	return time.Now().Before(b.openUntil)
}

func (c *Client) recordFailure(path string) {
	c.breakerMu.Lock()
	defer c.breakerMu.Unlock()
	b, ok := c.breakers[path]
	if !ok {
		if len(c.breakers) > 4096 {
			c.breakers = map[string]*breaker{}
		}
		b = &breaker{}
		c.breakers[path] = b
	}
	b.consecutive++
	if b.consecutive >= c.BreakerThreshold {
		b.openUntil = time.Now().Add(c.BreakerCooldown)
		b.consecutive = 0
		c.BreakerTrips.add(1)
		if c.Logf != nil {
			c.Logf("exec-gate: circuit breaker OPEN for %s — failing open (allowing execs) for %s", path, c.BreakerCooldown)
		}
	}
}

func (c *Client) recordSuccess(path string) {
	c.breakerMu.Lock()
	defer c.breakerMu.Unlock()
	if b, ok := c.breakers[path]; ok {
		b.consecutive = 0
	}
}

var _ watchdog.Evaluator = (*Client)(nil)

// once initializes lazily. It uses sync.Once and NOT the connection lock: taking the connection lock here
// was a real defect — it made every Evaluate serialize on the in-flight request BEFORE the in-flight
// bound was consulted, so the semaphore could never overflow and a fork storm queued on a lock instead of
// failing open. The overflow test caught it.
func (c *Client) once() { c.initOnce.Do(c.init) }

// atomic64 is a tiny counter. sync/atomic would do, but keeping it here means the type's zero value works
// inside a struct literal a test builds by hand.
type atomic64 struct {
	mu sync.Mutex
	n  int64
}

func (a *atomic64) add(n int64) {
	a.mu.Lock()
	a.n += n
	a.mu.Unlock()
}

// Load returns the counter.
func (a *atomic64) Load() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}
