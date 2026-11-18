//go:build linux

package native

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"

	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

type interval struct {
	first netip.Addr
	last  netip.Addr
}

func prefixInterval(prefix netip.Prefix) interval {
	first := prefix.Masked().Addr()
	raw := first.AsSlice()
	for bit := prefix.Bits(); bit < first.BitLen(); bit++ {
		raw[bit/8] |= byte(1 << (7 - bit%8))
	}
	last, _ := netip.AddrFromSlice(raw)
	return interval{first, last}
}

func coalesce(input []interval) []interval {
	slices.SortFunc(input, func(a, b interval) int { return a.first.Compare(b.first) })
	out := input[:0]
	for _, current := range input {
		if len(out) != 0 {
			last := &out[len(out)-1]
			if current.first.Compare(last.last) <= 0 || current.first == last.last.Next() {
				if current.last.Compare(last.last) > 0 {
					last.last = current.last
				}
				continue
			}
		}
		out = append(out, current)
	}
	return out
}

func decodeInterval(raw json.RawMessage, bits int) (interval, error) {
	var endpoint string
	if json.Unmarshal(raw, &endpoint) == nil {
		addr, err := netip.ParseAddr(endpoint)
		if err != nil || addr.BitLen() != bits {
			return interval{}, fmt.Errorf("invalid address in native nft set")
		}
		return interval{addr, addr}, nil
	}
	var entry struct {
		Range  []netip.Addr `json:"range"`
		Prefix *struct {
			Address netip.Addr `json:"addr"`
			Length  int        `json:"len"`
		} `json:"prefix"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return interval{}, err
	}
	if entry.Prefix != nil && entry.Range == nil {
		prefix := netip.PrefixFrom(entry.Prefix.Address, entry.Prefix.Length)
		if prefix.IsValid() && prefix.Addr().BitLen() == bits {
			return prefixInterval(prefix), nil
		}
	}
	if entry.Prefix == nil && len(entry.Range) == 2 && entry.Range[0].BitLen() == bits &&
		entry.Range[1].BitLen() == bits && entry.Range[0].Compare(entry.Range[1]) <= 0 {
		return interval{entry.Range[0], entry.Range[1]}, nil
	}
	return interval{}, fmt.Errorf("invalid interval in native nft set")
}

func VerifyCapture(config policy.Config, approved policy.Approved) error {
	if !config.IsNative() {
		return fmt.Errorf("configuration does not use native v2rayA")
	}
	table, ipv4, ipv6 := proxyTable, "whitelist", "whitelist6"
	if config.NativeTUN {
		table, ipv4, ipv6 = captureTable, "direct4", "direct6"
	}
	data, err := system.Command("", "nft", "--json", "list", "table", "inet", table)
	if err != nil {
		return err
	}
	var result struct {
		Objects []struct {
			Set *struct {
				Name     string            `json:"name"`
				Elements []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	for _, bits := range []int{32, 128} {
		name := ipv4
		if bits == 128 {
			name = ipv6
		}
		var want, got []interval
		found := false
		for _, p := range approved.Prefixes {
			if p.Addr().BitLen() == bits {
				want = append(want, prefixInterval(p))
			}
		}
		for _, obj := range result.Objects {
			if obj.Set == nil || obj.Set.Name != name {
				continue
			}
			found = true
			for _, elem := range obj.Set.Elements {
				range_, err := decodeInterval(elem, bits)
				if err != nil {
					return err
				}
				got = append(got, range_)
			}
		}
		if !found || !slices.Equal(coalesce(want), coalesce(got)) {
			return fmt.Errorf("loaded native nft set %s differs from the approved policy", name)
		}
	}
	return nil
}
