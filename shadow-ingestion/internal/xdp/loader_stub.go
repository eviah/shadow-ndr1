// Stub implementation for non-Linux platforms. Lets the rest of the
// service compile (and the unit tests run) on Windows / macOS dev boxes.

//go:build !linux

package xdp

import "errors"

const (
	StatTotal     = 0
	StatDropBlack = 1
	StatDropPort  = 2
	StatPass      = 3
	StatMalformed = 4
	StatNonIP     = 5
	StatNonTCPUDP = 6
	NumStats      = 8
)

type Loader struct{}
type Stats [NumStats]uint64

var ErrUnsupported = errors.New("xdp: only supported on linux")

func Attach(_, _ string) (*Loader, error)              { return nil, ErrUnsupported }
func (l *Loader) Close() error                         { return nil }
func (l *Loader) AddBlacklist(_ string) error          { return ErrUnsupported }
func (l *Loader) RemoveBlacklist(_ string) error       { return ErrUnsupported }
func (l *Loader) AddPortDrop(_ uint16) error           { return ErrUnsupported }
func (l *Loader) RemovePortDrop(_ uint16) error        { return ErrUnsupported }
func (l *Loader) ReadStats() (Stats, error)            { return Stats{}, ErrUnsupported }
