package guard

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

const (
	Direct uint32 = 1 << iota
	LAN
	Local
	DiagnosticClient
	DiagnosticDestination
)

const maxEntries = 20000

// Key matches struct prefix_key in bpf/guard.h. Family is part of the trie prefix.
type Key struct {
	PrefixLen uint32
	Family    uint32
	Address   [16]byte
}

func (k Key) Prefix() (netip.Prefix, error) {
	var addr netip.Addr
	switch k.Family {
	case 4:
		addr = netip.AddrFrom4([4]byte(k.Address[:4]))
		if [12]byte(k.Address[4:]) != [12]byte{} {
			return netip.Prefix{}, fmt.Errorf("IPv4 key has nonzero padding")
		}
	case 6:
		addr = netip.AddrFrom16(k.Address)
	default:
		return netip.Prefix{}, fmt.Errorf("unknown address family %d", k.Family)
	}
	bits := int64(k.PrefixLen) - 32
	if bits <= 0 || bits > int64(addr.BitLen()) {
		return netip.Prefix{}, fmt.Errorf("invalid key prefix length %d", k.PrefixLen)
	}
	prefix := netip.PrefixFrom(addr, int(bits))
	if prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("key address is not a network prefix: %s", prefix)
	}
	return prefix, nil
}

type Policy map[Key]uint32

func ParsePolicy(input io.Reader) (Policy, error) {
	entries := make(Policy)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 256), 256)
	for line := 1; scanner.Scan(); line++ {
		row := strings.Fields(scanner.Text())
		if len(row) != 3 {
			return nil, fmt.Errorf("policy line %d: expected FAMILY CIDR FLAGS", line)
		}
		prefix, err := netip.ParsePrefix(row[1])
		family := uint32(6)
		if prefix.Addr().Is4() {
			family = 4
		}
		flags, flagsErr := strconv.ParseUint(row[2], 10, 5)
		if err != nil || flagsErr != nil || strconv.FormatUint(uint64(family), 10) != row[0] {
			return nil, fmt.Errorf("policy line %d: invalid family, prefix or flags", line)
		}
		key := Key{PrefixLen: uint32(32 + prefix.Bits()), Family: family}
		copy(key.Address[:], prefix.Addr().AsSlice())
		if _, duplicate := entries[key]; duplicate {
			return nil, fmt.Errorf("policy line %d: duplicate prefix %s", line, prefix)
		}
		if len(entries) == maxEntries {
			return nil, fmt.Errorf("policy exceeds %d entries", maxEntries)
		}
		entries[key] = uint32(flags)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, entries.validate()
}

func (p Policy) validate() error {
	if len(p) < 1 || len(p) > maxEntries {
		return fmt.Errorf("policy must have between 1 and %d entries", maxEntries)
	}
	var clients, destinations int
	for key, flags := range p {
		prefix, err := key.Prefix()
		if err != nil {
			return err
		}
		if flags&^(Direct|LAN|Local|DiagnosticClient|DiagnosticDestination) != 0 ||
			flags&(Direct|DiagnosticDestination) == 0 ||
			flags&LAN != 0 && flags&Direct == 0 ||
			flags&Local != 0 && flags&(Direct|LAN) != Direct|LAN {
			return fmt.Errorf("invalid policy flags %d for %s", flags, prefix)
		}
		switch flags & (DiagnosticClient | DiagnosticDestination) {
		case 0:
		case DiagnosticClient:
			if key.Family != 4 || prefix.Bits() != 32 || flags != Direct|LAN|DiagnosticClient {
				return fmt.Errorf("invalid diagnostic client %s", prefix)
			}
			clients++
		case DiagnosticDestination:
			if key.Family != 4 || prefix.Bits() != 32 || flags&(LAN|Local) != 0 {
				return fmt.Errorf("invalid diagnostic destination %s", prefix)
			}
			destinations++
		default:
			return fmt.Errorf("conflicting diagnostic roles for %s", prefix)
		}
	}
	if clients != destinations || clients > 1 {
		return fmt.Errorf("policy must specify at most one complete diagnostic pair")
	}
	return nil
}
