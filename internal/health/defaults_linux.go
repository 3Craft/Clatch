//go:build linux

package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"

	"clatch-gateway/internal/policy"
)

type Defaults struct {
	DNS           string       `json:"dns,omitempty"`
	ExpectedExits []netip.Addr `json:"expected_exits,omitempty"`
	Conntrack     bool         `json:"conntrack,omitempty"`
	EmptyAAAA     bool         `json:"expect_empty_aaaa,omitempty"`
}

func ReadDefaults(config string) (Defaults, error) {
	var defaults Defaults
	path := filepath.Join(filepath.Dir(config), "health.json")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return defaults, nil
	}
	if err != nil {
		return defaults, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&defaults); err != nil {
		return defaults, fmt.Errorf("%s: %w", path, err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return defaults, fmt.Errorf("%s: unexpected trailing JSON", path)
	}
	for _, address := range defaults.ExpectedExits {
		if !address.Is4() {
			return defaults, fmt.Errorf("%s: expected_exits must contain IPv4 addresses", path)
		}
	}
	if defaults.DNS != "" {
		if _, err := ParseResolver(defaults.DNS); err != nil {
			return defaults, fmt.Errorf("%s: %w", path, err)
		}
	}
	return defaults, nil
}

func ParseResolver(value string) (netip.AddrPort, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		ip, err := netip.ParseAddr(value)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("invalid DNS endpoint %q", value)
		}
		address = netip.AddrPortFrom(ip, 53)
	}
	if !address.Addr().Is4() || address.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("health requires an IPv4 DNS endpoint")
	}
	return address, nil
}

func LocalResolver(config policy.Config) netip.AddrPort {
	var address netip.Addr
	for _, prefix := range config.LocalPrefixes {
		if prefix.Addr().Is4() {
			if address.IsValid() {
				return netip.AddrPort{}
			}
			address = prefix.Addr()
		}
	}
	if address.IsValid() {
		return netip.AddrPortFrom(address, 53)
	}
	return netip.AddrPort{}
}
