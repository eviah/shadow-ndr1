package chbatch

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sony/gobreaker"
)

type row struct {
	id int
}

// fakeFlusher records calls and returns scripted errors.
type fakeFlusher struct {
	mu     sync.Mutex
	calls  [][]row
	errs   []error // popped in order; nil = success
	delay  time.Duration
	calln  atomic.Int64
}

func (f *fakeFlusher) Flush(ctx context.Context, rows []row) error {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.calln.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]row, len(rows))
	copy(cp, rows)
	f.calls = append(f.calls, cp)
	if len(f.errs) == 0 {
		return nil
	}
	e := f.errs[0]
	f.errs = f.errs[1:]
	return e
}

func (f *fakeFlusher) recorded() [][]row {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]row, len(f.calls))
	copy(out, f.calls)
	return out
}

func defaultCfg() Config {
	return Config{
		MaxRows:          4,
		MaxAge:           50 * time.Millisecond,
		FlushTimeout:    1 * time.Second,
		MaxRetries:       2,
		BackoffBase:      1 * time.Millisecond,
		BackoffMax:       5 * time.Millisecond,
		BreakerThreshold: 3,
		OpenInterval:     50 * time.Millisecond,
	}
}

func TestNew_RejectsBadConfig(t *testing.T) {
	cases := []Config{
		{MaxRows: 0, MaxAge: 1 * time.Second},
		{MaxRows: 10, MaxAge: 0},
	}
	for i, c := range cases {
		if _, err := New[row](c, &fakeFlusher{}); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

func TestAdd_FlushesAtMaxRows(t *testing.T) {
	f := &fakeFlusher{}
	b, err := New[row](defaultCfg(), f)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(context.Background())

	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if err := b.Add(ctx, row{id: i}); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}
	calls := f.recorded()
	if len(calls) != 1 {
		t.Fatalf("flushes = %d, want 1", len(calls))
	}
	if len(calls[0]) != 4 {
		t.Errorf("batch size = %d, want 4", len(calls[0]))
	}

	s := b.Stats()
	if s.RowsIn != 4 || s.RowsFlushed != 4 || s.Batches != 1 {
		t.Errorf("stats = %+v", s)
	}
}

func TestFlush_TimeBased(t *testing.T) {
	f := &fakeFlusher{}
	cfg := defaultCfg()
	cfg.MaxAge = 30 * time.Millisecond
	b, err := New[row](cfg, f)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(context.Background())

	_ = b.Add(context.Background(), row{id: 1})

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(f.recorded()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(f.recorded()) != 1 {
		t.Fatalf("expected 1 timer-driven flush, got %d", len(f.recorded()))
	}
}

func TestFlush_RetriesOnTransientError(t *testing.T) {
	f := &fakeFlusher{
		errs: []error{errors.New("blip 1"), errors.New("blip 2"), nil},
	}
	cfg := defaultCfg()
	cfg.MaxRetries = 3
	b, err := New[row](cfg, f)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(context.Background())

	for i := 0; i < 4; i++ {
		_ = b.Add(context.Background(), row{id: i})
	}

	s := b.Stats()
	if s.Retries != 2 {
		t.Errorf("Retries = %d, want 2", s.Retries)
	}
	if s.RowsFlushed != 4 {
		t.Errorf("RowsFlushed = %d, want 4", s.RowsFlushed)
	}
	if s.RowsDropped != 0 {
		t.Errorf("RowsDropped = %d, want 0", s.RowsDropped)
	}
}

func TestFlush_PermanentErrorBypassesRetry(t *testing.T) {
	f := &fakeFlusher{
		errs: []error{Permanent(errors.New("schema mismatch"))},
	}
	cfg := defaultCfg()
	cfg.MaxRetries = 5

	var dlqRows []any
	var dlqErr error
	cfg.OnDeadLetter = func(rows []any, err error) {
		dlqRows = rows
		dlqErr = err
	}

	b, err := New[row](cfg, f)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(context.Background())

	for i := 0; i < 4; i++ {
		_ = b.Add(context.Background(), row{id: i})
	}

	if got := f.calln.Load(); got != 1 {
		t.Errorf("flusher called %d times, want exactly 1 (permanent skips retry)", got)
	}
	if len(dlqRows) != 4 {
		t.Errorf("DLQ rows = %d, want 4", len(dlqRows))
	}
	if !errors.Is(dlqErr, ErrPermanent) {
		t.Errorf("DLQ err = %v, want wraps ErrPermanent", dlqErr)
	}
}

func TestBreaker_OpensAfterConsecutiveFailures(t *testing.T) {
	f := &fakeFlusher{
		errs: []error{
			errors.New("e1"), errors.New("e2"), errors.New("e3"),
			errors.New("e4"), errors.New("e5"), errors.New("e6"),
			errors.New("e7"), errors.New("e8"), errors.New("e9"),
		},
	}
	cfg := defaultCfg()
	cfg.MaxRetries = 0 // each Add → 1 attempt → 1 breaker failure
	cfg.BreakerThreshold = 3
	cfg.OpenInterval = 200 * time.Millisecond

	dlqHits := atomic.Int64{}
	cfg.OnDeadLetter = func(rows []any, err error) {
		dlqHits.Add(1)
	}

	b, err := New[row](cfg, f)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(context.Background())

	// Drive 5 batches; first 3 trip the breaker, the rest should not even
	// reach the flusher.
	for batch := 0; batch < 5; batch++ {
		for i := 0; i < 4; i++ {
			_ = b.Add(context.Background(), row{id: batch*4 + i})
		}
	}

	if got := f.calln.Load(); got > 4 {
		t.Errorf("flusher called %d times — breaker did not open", got)
	}
	if dlqHits.Load() != 5 {
		t.Errorf("DLQ hits = %d, want 5", dlqHits.Load())
	}
	state := b.BreakerState()
	if state != gobreaker.StateOpen && state != gobreaker.StateHalfOpen {
		t.Errorf("breaker state = %v, want Open or HalfOpen", state)
	}
	s := b.Stats()
	if s.BreakerOpen == 0 {
		t.Errorf("BreakerOpen counter = 0, want > 0")
	}
}

func TestClose_FlushesPending(t *testing.T) {
	f := &fakeFlusher{}
	b, err := New[row](defaultCfg(), f)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ { // less than MaxRows=4
		_ = b.Add(context.Background(), row{id: i})
	}
	if len(f.recorded()) != 0 {
		t.Fatalf("unexpected flush before close")
	}

	if err := b.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(f.recorded()) != 1 || len(f.recorded()[0]) != 3 {
		t.Errorf("close flush = %v", f.recorded())
	}
}

func TestConcurrentAdd_NoLostRows(t *testing.T) {
	f := &fakeFlusher{}
	cfg := defaultCfg()
	cfg.MaxRows = 64
	cfg.MaxAge = 10 * time.Millisecond
	b, err := New[row](cfg, f)
	if err != nil {
		t.Fatal(err)
	}

	const (
		producers = 8
		each      = 500
	)
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				_ = b.Add(context.Background(), row{id: p*1000 + i})
			}
		}(p)
	}
	wg.Wait()

	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	total := 0
	for _, c := range f.recorded() {
		total += len(c)
	}
	if total != producers*each {
		t.Errorf("total rows = %d, want %d", total, producers*each)
	}
	s := b.Stats()
	if s.RowsFlushed != uint64(producers*each) {
		t.Errorf("RowsFlushed = %d, want %d", s.RowsFlushed, producers*each)
	}
}
