// Package chbatch provides a batched writer with circuit breaker and
// exponential-backoff retry, designed for ClickHouse but parameterised
// over any sink that implements Flusher.
//
// Why this design:
//   - ClickHouse's `INSERT` performs best with batches of 10k–100k rows.
//     A row-at-a-time call path collapses under load (one merge per
//     insert, no compression amortisation, etc.).
//   - The circuit breaker (sony/gobreaker) trips after a configurable
//     burst of consecutive failures, holding subsequent flushes in a
//     short open state to give the cluster time to recover instead of
//     amplifying the outage with retry storms.
//   - Backoff is exponential with full jitter (Marc Brooker's
//     recommendation) so independent ingest replicas don't synchronise
//     their retries and hammer ClickHouse in lockstep after a transient
//     error.
//
// The batcher is unit-testable because it depends only on the Flusher
// interface — tests inject a fake that returns scripted errors. The
// real adapter for github.com/ClickHouse/clickhouse-go/v2 is wired up
// at the call site (see Wire example in chbatch_test.go).
package chbatch

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sony/gobreaker"
)

// Flusher is the unit of work the batcher delegates to. Implementations
// translate a slice of rows into a single backend write (e.g., one
// ClickHouse INSERT). The context carries the per-flush deadline.
type Flusher[T any] interface {
	Flush(ctx context.Context, rows []T) error
}

// FlusherFunc adapts a function literal to the Flusher interface.
type FlusherFunc[T any] func(ctx context.Context, rows []T) error

func (f FlusherFunc[T]) Flush(ctx context.Context, rows []T) error { return f(ctx, rows) }

// Config tunes the batcher. Defaults are sensible for ClickHouse +
// 10k-row INSERT pattern; callers should still set MaxRows from their
// own load tests.
type Config struct {
	// MaxRows triggers a flush when the staging buffer reaches this size.
	// Required (must be > 0).
	MaxRows int

	// MaxAge triggers a flush after this much time has elapsed since the
	// first staged row, even if MaxRows is not yet hit. Required (> 0).
	MaxAge time.Duration

	// FlushTimeout bounds a single Flush call. After this, the context
	// fires and the underlying driver is expected to abort.
	FlushTimeout time.Duration

	// MaxRetries on transient flush failures. Set to 0 to disable
	// retries (rows go straight to the dead-letter handler on first
	// failure). Permanent errors (see ErrPermanent) bypass retries.
	MaxRetries int

	// BackoffBase is the base for exponential backoff with full jitter:
	// sleep = rand[0, base * 2^attempt). Capped at BackoffMax.
	BackoffBase time.Duration
	BackoffMax  time.Duration

	// BreakerName is shown in metrics. BreakerThreshold is the number of
	// consecutive failures that trips the breaker; OpenInterval is how
	// long the breaker stays open before half-open probing.
	BreakerName      string
	BreakerThreshold uint32
	OpenInterval     time.Duration

	// OnDeadLetter is invoked for rows the batcher gives up on (max
	// retries exhausted, or breaker open + WaitTimeout exceeded). The
	// caller is expected to write the rows to a parking lot — local file,
	// Kafka DLQ, etc. — and never block in here.
	OnDeadLetter func(rows []any, cause error)
}

// ErrPermanent wraps an error the caller wants to skip retries on.
// The batcher unwraps and routes the rows straight to OnDeadLetter.
var ErrPermanent = errors.New("chbatch: permanent error, no retry")

// Permanent marks an error as non-retryable.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrPermanent, err)
}

// Stats are read-only snapshots; safe to call concurrently.
type Stats struct {
	RowsIn      uint64
	RowsFlushed uint64
	RowsDropped uint64
	Batches     uint64
	Retries     uint64
	BreakerOpen uint64
	FlushErrors uint64
}

// Batcher accumulates rows and flushes them via a Flusher. One Batcher
// per (table, column-set) is the typical usage.
type Batcher[T any] struct {
	cfg     Config
	flusher Flusher[T]
	cb      *gobreaker.CircuitBreaker

	mu     sync.Mutex
	buf    []T
	bornAt time.Time

	// Counters. Atomically updated; safe for cross-goroutine reads.
	rowsIn      atomic.Uint64
	rowsFlushed atomic.Uint64
	rowsDropped atomic.Uint64
	batches     atomic.Uint64
	retries     atomic.Uint64
	breakerOpen atomic.Uint64
	flushErrors atomic.Uint64

	// Periodic flush ticker.
	stop   chan struct{}
	stopWG sync.WaitGroup
	rng    *rand.Rand
	rngMu  sync.Mutex
}

// New constructs a Batcher and starts the periodic max-age flusher.
// Call Close to stop the goroutine and flush remaining rows.
func New[T any](cfg Config, flusher Flusher[T]) (*Batcher[T], error) {
	if cfg.MaxRows <= 0 {
		return nil, errors.New("chbatch: MaxRows must be > 0")
	}
	if cfg.MaxAge <= 0 {
		return nil, errors.New("chbatch: MaxAge must be > 0")
	}
	if cfg.FlushTimeout <= 0 {
		cfg.FlushTimeout = 30 * time.Second
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 100 * time.Millisecond
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 30 * time.Second
	}
	if cfg.BreakerThreshold == 0 {
		cfg.BreakerThreshold = 5
	}
	if cfg.OpenInterval <= 0 {
		cfg.OpenInterval = 30 * time.Second
	}
	if cfg.BreakerName == "" {
		cfg.BreakerName = "chbatch"
	}
	if cfg.OnDeadLetter == nil {
		// Default: discard with stats only. SREs see RowsDropped go up.
		cfg.OnDeadLetter = func([]any, error) {}
	}

	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        cfg.BreakerName,
		MaxRequests: 1,
		Interval:    cfg.OpenInterval, // count window for closed-state failures
		Timeout:     cfg.OpenInterval, // open → half-open after this
		ReadyToTrip: func(c gobreaker.Counts) bool {
			return c.ConsecutiveFailures >= cfg.BreakerThreshold
		},
	})

	b := &Batcher[T]{
		cfg:     cfg,
		flusher: flusher,
		cb:      cb,
		buf:     make([]T, 0, cfg.MaxRows),
		stop:    make(chan struct{}),
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	b.stopWG.Add(1)
	go b.tickLoop()
	return b, nil
}

// Add stages a row. Triggers a synchronous flush if the buffer reaches
// MaxRows. Returns the flush error (if any) so the caller can decide
// whether to back off the upstream queue. Errors during a triggered
// flush do NOT lose rows: they are routed to OnDeadLetter.
func (b *Batcher[T]) Add(ctx context.Context, row T) error {
	b.rowsIn.Add(1)
	b.mu.Lock()
	if len(b.buf) == 0 {
		b.bornAt = time.Now()
	}
	b.buf = append(b.buf, row)
	full := len(b.buf) >= b.cfg.MaxRows
	b.mu.Unlock()
	if full {
		return b.Flush(ctx)
	}
	return nil
}

// Flush forces an immediate flush of the staged rows. Idempotent on
// empty buffer.
func (b *Batcher[T]) Flush(ctx context.Context) error {
	b.mu.Lock()
	if len(b.buf) == 0 {
		b.mu.Unlock()
		return nil
	}
	rows := b.buf
	b.buf = make([]T, 0, b.cfg.MaxRows)
	b.mu.Unlock()
	return b.flushWithRetry(ctx, rows)
}

// Close flushes remaining rows and stops the periodic flusher.
func (b *Batcher[T]) Close(ctx context.Context) error {
	close(b.stop)
	b.stopWG.Wait()
	return b.Flush(ctx)
}

// Stats returns a snapshot of the lifetime counters.
func (b *Batcher[T]) Stats() Stats {
	return Stats{
		RowsIn:      b.rowsIn.Load(),
		RowsFlushed: b.rowsFlushed.Load(),
		RowsDropped: b.rowsDropped.Load(),
		Batches:     b.batches.Load(),
		Retries:     b.retries.Load(),
		BreakerOpen: b.breakerOpen.Load(),
		FlushErrors: b.flushErrors.Load(),
	}
}

// BreakerState exposes the current breaker state for /healthz endpoints.
func (b *Batcher[T]) BreakerState() gobreaker.State { return b.cb.State() }

func (b *Batcher[T]) tickLoop() {
	defer b.stopWG.Done()
	tick := time.NewTicker(b.cfg.MaxAge / 2)
	defer tick.Stop()
	for {
		select {
		case <-b.stop:
			return
		case now := <-tick.C:
			b.mu.Lock()
			ready := len(b.buf) > 0 && now.Sub(b.bornAt) >= b.cfg.MaxAge
			b.mu.Unlock()
			if ready {
				ctx, cancel := context.WithTimeout(context.Background(), b.cfg.FlushTimeout)
				_ = b.Flush(ctx)
				cancel()
			}
		}
	}
}

func (b *Batcher[T]) flushWithRetry(ctx context.Context, rows []T) error {
	if len(rows) == 0 {
		return nil
	}
	var lastErr error
	for attempt := 0; attempt <= b.cfg.MaxRetries; attempt++ {
		_, err := b.cb.Execute(func() (any, error) {
			fctx, cancel := context.WithTimeout(ctx, b.cfg.FlushTimeout)
			defer cancel()
			return nil, b.flusher.Flush(fctx, rows)
		})

		if err == nil {
			b.rowsFlushed.Add(uint64(len(rows)))
			b.batches.Add(1)
			return nil
		}

		// Breaker open → no point retrying inside this call.
		if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
			b.breakerOpen.Add(1)
			lastErr = err
			break
		}

		b.flushErrors.Add(1)
		lastErr = err

		if errors.Is(err, ErrPermanent) {
			break
		}
		if attempt == b.cfg.MaxRetries {
			break
		}
		// caller cancelled the upstream context — abort.
		if ctx.Err() != nil {
			break
		}
		b.retries.Add(1)
		b.sleepBackoff(ctx, attempt)
	}

	// Give up: hand rows to the dead-letter sink.
	b.rowsDropped.Add(uint64(len(rows)))
	anyRows := make([]any, len(rows))
	for i := range rows {
		anyRows[i] = rows[i]
	}
	b.cfg.OnDeadLetter(anyRows, lastErr)
	return lastErr
}

func (b *Batcher[T]) sleepBackoff(ctx context.Context, attempt int) {
	// sleep = uniform[0, base * 2^attempt), capped at BackoffMax.
	exp := uint(attempt)
	if exp > 30 {
		exp = 30 // avoid uint shift overflow
	}
	upper := b.cfg.BackoffBase * time.Duration(1<<exp)
	if upper > b.cfg.BackoffMax || upper <= 0 {
		upper = b.cfg.BackoffMax
	}
	b.rngMu.Lock()
	d := time.Duration(b.rng.Int63n(int64(upper)))
	b.rngMu.Unlock()

	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	case <-b.stop:
	}
}
