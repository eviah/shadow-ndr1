// Package xdp loads and manages the Shadow NDR XDP fast-path filter.
//
// On Linux this attaches the compiled eBPF object at ../../ebpf/xdp_fastpath.o
// to a network interface in XDP_DRV mode where supported, falling back to
// XDP_GENERIC. On every other OS the package compiles to no-op stubs so the
// rest of the ingestion service can build and unit-test on Windows / macOS.
//
// Build the eBPF object first (Linux + clang + libbpf-dev):
//
//	cd shadow-ingestion/ebpf && clang -O2 -g -Wall -target bpf \
//	    -c xdp_fastpath.c -o xdp_fastpath.o
//
// Then attach from Go:
//
//	loader, err := xdp.Attach("eth0", "ebpf/xdp_fastpath.o")
//	defer loader.Close()
//	loader.AddBlacklist("10.20.30.0/24")
//	loader.AddPortDrop(23)
//	stats := loader.ReadStats()

//go:build linux

package xdp

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// StatsSlot constants mirror the per-CPU array slots in the C program.
const (
	StatTotal       = 0
	StatDropBlack   = 1
	StatDropPort    = 2
	StatPass        = 3
	StatMalformed   = 4
	StatNonIP       = 5
	StatNonTCPUDP   = 6
	NumStats        = 8
	maxBlacklistEnt = 4096
	maxPortEnt      = 256
)

type lpmV4Key struct {
	PrefixLen uint32
	Addr      uint32
}

type Loader struct {
	coll       *ebpf.Collection
	link       link.Link
	blackMap   *ebpf.Map
	portMap    *ebpf.Map
	statsMap   *ebpf.Map
	ifaceIndex int
}

// Attach loads the compiled eBPF object and attaches it to the interface.
func Attach(ifaceName, objectPath string) (*Loader, error) {
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}
	prog := coll.Programs["xdp_fastpath"]
	if prog == nil {
		coll.Close()
		return nil, errors.New("xdp_fastpath program missing")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("interface %q: %w", ifaceName, err)
	}

	// Try DRV first; fall back to GENERIC.
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("attach xdp: %w", err)
		}
	}

	return &Loader{
		coll:       coll,
		link:       xdpLink,
		blackMap:   coll.Maps["blacklist_v4"],
		portMap:    coll.Maps["port_drop"],
		statsMap:   coll.Maps["stats"],
		ifaceIndex: iface.Index,
	}, nil
}

// Close detaches the program and releases all resources.
func (l *Loader) Close() error {
	if l.link != nil {
		l.link.Close()
	}
	if l.coll != nil {
		l.coll.Close()
	}
	return nil
}

// AddBlacklist installs an IPv4 prefix in the LPM trie.
// cidr like "10.20.30.0/24" or "192.168.1.42/32".
func (l *Loader) AddBlacklist(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	prefix, _ := ipnet.Mask.Size()
	v4 := ipnet.IP.To4()
	if v4 == nil {
		return errors.New("not an IPv4 prefix")
	}
	addr := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	// Network byte order required by the kernel LPM lookup.
	addrBE := htonl(addr)
	key := lpmV4Key{PrefixLen: uint32(prefix), Addr: addrBE}
	val := uint8(1)
	return l.blackMap.Update(&key, &val, ebpf.UpdateAny)
}

// RemoveBlacklist deletes a prefix.
func (l *Loader) RemoveBlacklist(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	prefix, _ := ipnet.Mask.Size()
	v4 := ipnet.IP.To4()
	addr := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	key := lpmV4Key{PrefixLen: uint32(prefix), Addr: htonl(addr)}
	return l.blackMap.Delete(&key)
}

// AddPortDrop installs a TCP/UDP destination port in the drop set.
func (l *Loader) AddPortDrop(port uint16) error {
	val := uint8(1)
	return l.portMap.Update(&port, &val, ebpf.UpdateAny)
}

// RemovePortDrop removes a port from the drop set.
func (l *Loader) RemovePortDrop(port uint16) error {
	return l.portMap.Delete(&port)
}

// Stats is the per-counter snapshot.
type Stats [NumStats]uint64

// ReadStats sums per-CPU values for each slot.
func (l *Loader) ReadStats() (Stats, error) {
	var out Stats
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return out, err
	}
	for slot := uint32(0); slot < NumStats; slot++ {
		vals := make([]uint64, ncpu)
		if err := l.statsMap.Lookup(&slot, &vals); err != nil {
			return out, fmt.Errorf("lookup slot %d: %w", slot, err)
		}
		var sum uint64
		for _, v := range vals {
			sum += v
		}
		out[slot] = sum
	}
	return out, nil
}

func htonl(x uint32) uint32 {
	return ((x & 0x000000FF) << 24) |
		((x & 0x0000FF00) << 8) |
		((x & 0x00FF0000) >> 8) |
		((x & 0xFF000000) >> 24)
}
