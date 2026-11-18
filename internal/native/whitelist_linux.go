//go:build linux

package native

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// EditWhitelist preserves v2rayA-owned fields and the identity of individual
// CIDRs. Two adjacent entries can be removed independently.
func EditWhitelist(raw json.RawMessage, action string, values []string, replace bool) (json.RawMessage, []string, []string, error) {
	data, err := decodeWhitelist(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	before, err := exactNetworks(data.Custom)
	if err != nil {
		return nil, nil, nil, err
	}
	input, err := exactNetworks(values)
	if err != nil {
		return nil, nil, nil, err
	}
	after := slices.Clone(before)
	switch action {
	case "show", "refresh":
		return raw, []string{}, []string{}, nil
	case "add", "import":
		if len(input) == 0 {
			return nil, nil, nil, fmt.Errorf("no custom IPs supplied")
		}
		if replace {
			after = input
		} else {
			after = append(after, input...)
			sortNetworks(after)
			after = slices.Compact(after)
		}
	case "remove":
		if len(input) == 0 {
			return nil, nil, nil, fmt.Errorf("no custom IPs supplied")
		}
		for _, item := range input {
			if !slices.Contains(before, item) {
				return nil, nil, nil, fmt.Errorf("no exact custom entry %s", item)
			}
		}
		after = slices.DeleteFunc(after, func(value netip.Prefix) bool { return slices.Contains(input, value) })
	case "restore":
		after = input
	default:
		return nil, nil, nil, fmt.Errorf("unknown native whitelist action")
	}
	added, removed := difference(after, before), difference(before, after)
	if len(added) == 0 && len(removed) == 0 {
		return raw, added, removed, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, nil, nil, err
	}
	values = make([]string, 0, len(after))
	for _, item := range after {
		values = append(values, item.String())
	}
	fields["customIps"], err = json.Marshal(values)
	if err != nil {
		return nil, nil, nil, err
	}
	result, err := json.Marshal(fields)
	return result, added, removed, err
}

func CustomIPs(raw json.RawMessage) ([]string, error) {
	data, err := decodeWhitelist(raw)
	return data.Custom, err
}

func exactNetworks(values []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		p, err := netip.ParsePrefix(value)
		if err != nil {
			a, addrErr := netip.ParseAddr(value)
			if addrErr != nil {
				return nil, fmt.Errorf("invalid IP or CIDR %q", value)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if !p.IsValid() || p.Masked() != p || p.Bits() == 0 {
			return nil, fmt.Errorf("invalid or unrestricted CIDR %q", value)
		}
		out = append(out, p)
	}
	sortNetworks(out)
	return slices.Compact(out), nil
}

func sortNetworks(values []netip.Prefix) {
	slices.SortFunc(values, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
}

func difference(a, b []netip.Prefix) []string {
	out := []string{}
	for _, item := range a {
		if !slices.Contains(b, item) {
			out = append(out, item.String())
		}
	}
	return out
}
