package chaos

import (
	"testing"
	"time"
)

func TestStubLoadFailsCleanly(t *testing.T) {
	if _, err := Load("nonexistent.o"); err == nil {
		t.Skip("running on Linux with privileges, skip stub test")
	}
}

func TestRuleStructFields(t *testing.T) {
	r := Rule{
		SyscallID:   SyscallRead,
		PIDFilter:   0,
		FailPer1K:   50,
		InjectErrno: 11, // EAGAIN
		ArmedFor:    30 * time.Second,
	}
	if r.SyscallID != SyscallRead {
		t.Fatalf("expected SyscallRead, got %d", r.SyscallID)
	}
	if r.FailPer1K != 50 {
		t.Fatalf("expected FailPer1K=50, got %d", r.FailPer1K)
	}
}

func TestEventChannelDoesNotBlockOnStub(t *testing.T) {
	var e Engine
	ch := e.Events()
	select {
	case <-ch:
		// closed channel returns zero immediately — fine.
	case <-time.After(100 * time.Millisecond):
		t.Fatal("stub event channel should be drained / closed")
	}
}
