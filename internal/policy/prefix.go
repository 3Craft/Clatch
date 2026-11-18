package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const maxPrefixes = 18999

// Parse canonicalizes CIDRs in the same address order used by legacy snapshots.
func Parse(values []string) ([]netip.Prefix, error) {
	if len(values) > maxPrefixes {
		return nil, fmt.Errorf("too many CIDRs: %d", len(values))
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return nil, fmt.Errorf("invalid or unrestricted CIDR %q", value)
		}
		prefixes = append(prefixes, prefix)
	}
	result := collapse(prefixes)
	if len(result) > 0 && (result[0].Bits() == 0 || result[len(result)-1].Bits() == 0) {
		return nil, fmt.Errorf("CIDR set would allow a whole address family")
	}
	return result, nil
}

func collapse(prefixes []netip.Prefix) []netip.Prefix {
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return a.Bits() - b.Bits()
	})
	stack := prefixes[:0]
	for _, prefix := range prefixes {
		covered := false
		for len(stack) > 0 {
			last := stack[len(stack)-1]
			if last.Contains(prefix.Addr()) && last.Bits() <= prefix.Bits() {
				covered = true
				break
			}
			if last.Bits() != prefix.Bits() || last.Bits() == 0 || last.Addr().BitLen() != prefix.Addr().BitLen() {
				break
			}
			parent := netip.PrefixFrom(prefix.Addr(), prefix.Bits()-1).Masked()
			if !parent.Contains(last.Addr()) {
				break
			}
			stack = stack[:len(stack)-1]
			prefix = parent
		}
		if !covered {
			stack = append(stack, prefix)
		}
	}
	return stack
}

func Strings(prefixes []netip.Prefix) []string {
	values := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		values = append(values, prefixString(prefix))
	}
	return values
}

func prefixString(prefix netip.Prefix) string {
	// Python ipaddress represents IPv4-mapped IPv6 as hexadecimal hextets.
	if prefix.Addr().Is4In6() {
		addr := prefix.Addr().As16()
		high := binary.BigEndian.Uint16(addr[12:14])
		low := binary.BigEndian.Uint16(addr[14:])
		return fmt.Sprintf("::ffff:%x:%x/%d", high, low, prefix.Bits())
	}
	return prefix.String()
}

func Digest(prefixes []netip.Prefix) string {
	data, _ := json.Marshal(Strings(prefixes))
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func Match(prefixes []netip.Prefix, target netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Bits() <= target.Bits() && prefix.Contains(target.Addr()) {
			return true
		}
	}
	return false
}

func Intersect(a, b []netip.Prefix) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, min(len(a), len(b)))
	for len(a) > 0 && len(b) > 0 {
		first, second := a[0], b[0]
		switch {
		case first.Bits() <= second.Bits() && first.Contains(second.Addr()):
			prefixes = append(prefixes, second)
			b = b[1:]
		case second.Bits() <= first.Bits() && second.Contains(first.Addr()):
			prefixes = append(prefixes, first)
			a = a[1:]
		case first.Addr().Compare(second.Addr()) < 0:
			a = a[1:]
		default:
			b = b[1:]
		}
	}
	return collapse(prefixes)
}

func Elements(prefixes []netip.Prefix, bits int) string {
	var values []string
	for _, prefix := range prefixes {
		if prefix.Addr().BitLen() == bits {
			values = append(values, prefixString(prefix))
		}
	}
	return strings.Join(values, ", ")
}
