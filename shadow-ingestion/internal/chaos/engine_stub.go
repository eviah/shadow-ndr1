// Stub implementation for non-Linux platforms. The chaos engine is Linux-
// only because it requires BPF_FUNC_override_return; on other platforms the
// public surface is preserved so callers can build everywhere.

//go:build !linux

package chaos

import (
	"errors"
	"time"
)

const (
	SyscallRead    uint32 = 0
	SyscallOpenat  uint32 = 257
	SyscallConnect uint32 = 42
	SyscallSendmsg uint32 = 46
	SyscallRecvmsg uint32 = 47
)

type Rule struct {
	SyscallID   uint32
	PIDFilter   uint32
	FailPer1K   uint32
	InjectErrno int32
	ArmedFor    time.Duration
}

type Event struct {
	TimestampNs uint64
	PID         uint32
	SyscallID   uint32
	InjectErrno int32
}

type Engine struct{}

var ErrUnsupported = errors.New("chaos: only supported on linux with CONFIG_BPF_KPROBE_OVERRIDE")

func Load(_ string) (*Engine, error)            { return nil, ErrUnsupported }
func (e *Engine) Events() <-chan Event           { ch := make(chan Event); close(ch); return ch }
func (e *Engine) Arm(_ Rule) error               { return ErrUnsupported }
func (e *Engine) Disarm(_ uint32) error          { return ErrUnsupported }
func (e *Engine) Fired() (uint64, error)         { return 0, nil }
func (e *Engine) Close() error                   { return nil }
