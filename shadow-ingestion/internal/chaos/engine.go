// Package chaos drives the eBPF-based JIT chaos engineering engine.
//
// On Linux it loads `ebpf/chaos_inject.o`, attaches kprobes to the configured
// syscalls, and lets the controller arm/disarm fault-injection rules at
// runtime via `Arm` / `Disarm`. The compiled program emits a ringbuf event
// every time a rule fires, and the controller pumps those into a Go channel
// for observability.
//
// On non-Linux platforms the package compiles to no-ops so the rest of the
// service builds cleanly on Windows / macOS dev boxes.

//go:build linux

package chaos

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	SyscallRead    uint32 = 0
	SyscallOpenat  uint32 = 257
	SyscallConnect uint32 = 42
	SyscallSendmsg uint32 = 46
	SyscallRecvmsg uint32 = 47
)

type Rule struct {
	SyscallID    uint32
	PIDFilter    uint32
	FailPer1K    uint32
	InjectErrno  int32
	ArmedFor     time.Duration
}

type ruleStruct struct {
	SyscallID     uint32
	PIDFilter     uint32
	FailPer1K     uint32
	InjectErrno   int32
	ArmedUntilNs  uint64
}

type Event struct {
	TimestampNs uint64
	PID         uint32
	SyscallID   uint32
	InjectErrno int32
	_           uint32
}

type Engine struct {
	coll       *ebpf.Collection
	links      []link.Link
	rulesMap   *ebpf.Map
	countersMap *ebpf.Map
	rb         *ringbuf.Reader

	eventCh chan Event
	stop    chan struct{}
	wg      sync.WaitGroup
}

// Load attaches the eBPF object and starts the ringbuf consumer.
func Load(objectPath string) (*Engine, error) {
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}
	links := make([]link.Link, 0, 5)
	attach := func(progName, kfunc string) error {
		prog := coll.Programs[progName]
		if prog == nil {
			return fmt.Errorf("missing program %s", progName)
		}
		l, err := link.Kprobe(kfunc, prog, nil)
		if err != nil {
			return fmt.Errorf("attach %s: %w", kfunc, err)
		}
		links = append(links, l)
		return nil
	}
	for _, pair := range []struct{ prog, kfunc string }{
		{"chaos_read", "__x64_sys_read"},
		{"chaos_openat", "__x64_sys_openat"},
		{"chaos_connect", "__x64_sys_connect"},
		{"chaos_sendmsg", "__x64_sys_sendmsg"},
		{"chaos_recvmsg", "__x64_sys_recvmsg"},
	} {
		if err := attach(pair.prog, pair.kfunc); err != nil {
			for _, l := range links {
				l.Close()
			}
			coll.Close()
			return nil, err
		}
	}

	rb, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		coll.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	eng := &Engine{
		coll:        coll,
		links:       links,
		rulesMap:    coll.Maps["rules"],
		countersMap: coll.Maps["counters"],
		rb:          rb,
		eventCh:     make(chan Event, 1024),
		stop:        make(chan struct{}),
	}
	eng.wg.Add(1)
	go eng.pump()
	return eng, nil
}

func (e *Engine) pump() {
	defer e.wg.Done()
	for {
		select {
		case <-e.stop:
			return
		default:
		}
		rec, err := e.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if len(rec.RawSample) < 24 {
			continue
		}
		var ev Event
		ev.TimestampNs = leu64(rec.RawSample[0:8])
		ev.PID = leu32(rec.RawSample[8:12])
		ev.SyscallID = leu32(rec.RawSample[12:16])
		ev.InjectErrno = int32(leu32(rec.RawSample[16:20]))
		select {
		case e.eventCh <- ev:
		default:
			// drop on backpressure — chaos events are non-critical
		}
	}
}

func leu32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func leu64(b []byte) uint64 {
	return uint64(leu32(b[:4])) | uint64(leu32(b[4:8]))<<32
}

// Events returns the read-only channel of fault-injection events.
func (e *Engine) Events() <-chan Event { return e.eventCh }

// Arm installs (or replaces) a chaos rule.
func (e *Engine) Arm(r Rule) error {
	armedUntil := uint64(0)
	if r.ArmedFor > 0 {
		armedUntil = uint64(time.Now().UnixNano() + r.ArmedFor.Nanoseconds())
	}
	val := ruleStruct{
		SyscallID:    r.SyscallID,
		PIDFilter:    r.PIDFilter,
		FailPer1K:    r.FailPer1K,
		InjectErrno:  r.InjectErrno,
		ArmedUntilNs: armedUntil,
	}
	return e.rulesMap.Update(&r.SyscallID, &val, ebpf.UpdateAny)
}

// Disarm removes the rule for the given syscall.
func (e *Engine) Disarm(syscallID uint32) error {
	return e.rulesMap.Delete(&syscallID)
}

// Fired returns the total number of fault injections since boot.
func (e *Engine) Fired() (uint64, error) {
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, err
	}
	vals := make([]uint64, ncpu)
	var key uint32 = 0
	if err := e.countersMap.Lookup(&key, &vals); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range vals {
		sum += v
	}
	return sum, nil
}

func (e *Engine) Close() error {
	close(e.stop)
	if e.rb != nil {
		e.rb.Close()
	}
	for _, l := range e.links {
		l.Close()
	}
	if e.coll != nil {
		e.coll.Close()
	}
	e.wg.Wait()
	return nil
}
