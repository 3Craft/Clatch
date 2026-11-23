package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"clatch-gateway/internal/policy"
)

// DNSProbe configures a single domain + record type probe in health.json.
type DNSProbe struct {
	Domain string `json:"domain"`
	Type   string `json:"type"` // "A" or "AAAA"
}

type Defaults struct {
	DNS           string       `json:"dns,omitempty"`
	ExpectedExits []netip.Addr `json:"expected_exits,omitempty"`
	Conntrack     bool         `json:"conntrack,omitempty"`
	EmptyAAAA     bool         `json:"expect_empty_aaaa,omitempty"`
	DirectURL     string       `json:"direct_url,omitempty"`
	ProxyURL      string       `json:"proxy_url,omitempty"`
	DNSProbes     []DNSProbe   `json:"dns_probes,omitempty"`
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
	for _, item := range []struct{ field, raw string }{
		{"direct_url", defaults.DirectURL},
		{"proxy_url", defaults.ProxyURL},
	} {
		if item.raw == "" {
			continue
		}
		parsed, err := url.Parse(item.raw)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
			return defaults, fmt.Errorf("%s: %s must be an http or https URL", path, item.field)
		}
	}
	for i := range defaults.DNSProbes {
		probe := &defaults.DNSProbes[i]
		probe.Domain = strings.TrimSpace(probe.Domain)
		probe.Type = strings.ToUpper(strings.TrimSpace(probe.Type))
		if probe.Domain == "" || (probe.Type != "A" && probe.Type != "AAAA") {
			return defaults, fmt.Errorf("%s: dns_probes[%d] requires a non-empty domain and type A or AAAA", path, i)
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
