package ringbuf

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestNew_RoundsUpToPow2(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{1, 1}, {2, 2}, {3, 4}, {5, 8}, {1000, 1024}, {1024, 1024},
	}
	for _, c := range cases {
		r := New[int](c.in)
		if r.Capacity() != c.want {
			t.Errorf("New(%d).Capacity() = %d, want %d", c.in, r.Capacity(), c.want)
		}
	}
}

func TestNew_PanicsOnZero(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on capacity 0")
		}
	}()
	_ = New[int](0)
}

func TestPushPop_FIFOOrder(t *testing.T) {
	r := New[int](8)
	for i := 0; i < 8; i++ {
		if err := r.TryPush(i); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	if err := r.TryPush(99); !errors.Is(err, ErrFull) {
		t.Fatalf("expected ErrFull, got %v", err)
	}
	for i := 0; i < 8; i++ {
		got, err := r.TryPop()
		if err != nil {
			t.Fatalf("pop %d: %v", i, err)
		}
		if got != i {
			t.Errorf("pop %d = %d, want %d", i, got, i)
		}
	}
	if _, err := r.TryPop(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("expected ErrEmpty after drain, got %v", err)
	}
}

func TestPushPop_WrapsAround(t *testing.T) {
	r := New[int](4)
	// Fill, drain, fill again — exercises the seq lap-bump logic.
	for lap := 0; lap < 3; lap++ {
		for i := 0; i < 4; i++ {
			if err := r.TryPush(lap*10 + i); err != nil {
				t.Fatalf("lap %d push %d: %v", lap, i, err)
			}
		}
		for i := 0; i < 4; i++ {
			got, err := r.TryPop()
			if err != nil {
				t.Fatalf("lap %d pop %d: %v", lap, i, err)
			}
			if got != lap*10+i {
				t.Errorf("lap %d pop %d = %d, want %d", lap, i, got, lap*10+i)
			}
		}
	}
}

func TestStats_TrackPushPopDrop(t *testing.T) {
	r := New[int](2)
	_ = r.TryPush(1)
	_ = r.TryPush(2)
	_ = r.TryPush(3) // dropped
	_ = r.TryPush(4) // dropped
	_, _ = r.TryPop()

	s := r.Stats()
	if s.Pushed != 2 {
		t.Errorf("Pushed = %d, want 2", s.Pushed)
	}
	if s.Popped != 1 {
		t.Errorf("Popped = %d, want 1", s.Popped)
	}
	if s.Dropped != 2 {
		t.Errorf("Dropped = %d, want 2", s.Dropped)
	}
	if s.Pending != 1 {
		t.Errorf("Pending = %d, want 1", s.Pending)
	}
}

func TestConcurrent_MultiProducerSingleConsumer(t *testing.T) {
	const (
		producers       = 8
		perProducer     = 5000
		bufferCapacity  = 256
		expectedPushed  = producers * perProducer
	)
	r := New[uint64](bufferCapacity)

	var pushedTotal atomic.Uint64
	var droppedTotal atomic.Uint64
	var wg sync.WaitGroup

	// Consumer pops everything that was pushed (not dropped).
	consumed := make(map[uint64]int)
	var consumedMu sync.Mutex
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			v, err := r.TryPop()
			if err == nil {
				consumedMu.Lock()
				consumed[v]++
				consumedMu.Unlock()
				continue
			}
			select {
			case <-stop:
				// Drain whatever remains, then exit.
				for {
					v, err := r.TryPop()
					if err != nil {
						return
					}
					consumedMu.Lock()
					consumed[v]++
					consumedMu.Unlock()
				}
			default:
			}
		}
	}()

	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(base uint64) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				val := base*1_000_000 + uint64(i)
				for {
					err := r.TryPush(val)
					if err == nil {
						pushedTotal.Add(1)
						break
					}
					if errors.Is(err, ErrFull) {
						// Retry instead of dropping so test result is
						// deterministic. Counter still advances.
						droppedTotal.Add(1)
						continue
					}
				}
			}
		}(uint64(p))
	}

	// Wait for producers, then signal consumer to drain and exit.
	go func() {
		// Producer-only WaitGroup: rebuild via simple poll.
		for {
			if pushedTotal.Load() == expectedPushed {
				close(stop)
				return
			}
		}
	}()

	wg.Wait()

	if pushedTotal.Load() != expectedPushed {
		t.Fatalf("pushed = %d, want %d", pushedTotal.Load(), expectedPushed)
	}

	totalConsumed := 0
	for _, n := range consumed {
		totalConsumed += n
		if n != 1 {
			t.Errorf("value consumed %d times, want exactly 1", n)
		}
	}
	if totalConsumed != expectedPushed {
		t.Fatalf("consumed = %d, want %d", totalConsumed, expectedPushed)
	}

	s := r.Stats()
	if s.Pushed != expectedPushed {
		t.Errorf("Stats.Pushed = %d, want %d", s.Pushed, expectedPushed)
	}
	if s.Popped != expectedPushed {
		t.Errorf("Stats.Popped = %d, want %d", s.Popped, expectedPushed)
	}
}

func TestLen_BoundedByCapacity(t *testing.T) {
	r := New[int](4)
	for i := 0; i < 4; i++ {
		_ = r.TryPush(i)
	}
	if l := r.Len(); l != 4 {
		t.Errorf("Len = %d, want 4", l)
	}
	_, _ = r.TryPop()
	if l := r.Len(); l != 3 {
		t.Errorf("Len after pop = %d, want 3", l)
	}
}

func BenchmarkTryPushPop(b *testing.B) {
	r := New[int](1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.TryPush(i)
		_, _ = r.TryPop()
	}
}
