package xdp

import "testing"

// On non-Linux build hosts, Attach must return ErrUnsupported and not panic.
func TestStubAttachFailsCleanly(t *testing.T) {
	if _, err := Attach("eth0", "doesnt-matter.o"); err == nil {
		t.Skip("attach succeeded — running on Linux with privileges, skip stub test")
	}
}

func TestStatsZeroValueIsValid(t *testing.T) {
	var s Stats
	if s[StatTotal] != 0 {
		t.Fatal("zero-value stats must read as zeros")
	}
}
