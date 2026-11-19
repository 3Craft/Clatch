//go:build linux

package openwrt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"clatch-gateway/internal/policy"
)

type Uplink struct {
	Network string `json:"network"`
	Device  string `json:"device"`
}

type Config struct {
	Schema                 int      `json:"schema"`
	LANDevices             []string `json:"lan_devices"`
	LAN                    []string `json:"lan"`
	Uplinks                []Uplink `json:"uplinks"`
	Policy                 string   `json:"policy"`
	ProxyDevice            string   `json:"proxy_device,omitempty"`
	UnmanagedEgressDevices []string `json:"unmanaged_egress_devices,omitempty"`

	direct []netip.Prefix
	lan4   string
}

var networkName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func ReadConfig(path string) (Config, error) {
	var config Config
	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return config, fmt.Errorf("unexpected data after OpenWrt gateway config")
	}
	if config.Schema != 1 || len(config.LANDevices) == 0 || len(config.Uplinks) == 0 ||
		!filepath.IsAbs(config.Policy) || filepath.Clean(config.Policy) != config.Policy {
		return config, fmt.Errorf("OpenWrt config requires schema 1, LAN devices, uplinks and an absolute policy path")
	}
	seen := map[string]bool{"lo": true}
	for _, lan := range config.LANDevices {
		if !policy.ValidInterface(lan) || seen[lan] {
			return config, fmt.Errorf("invalid or repeated LAN device %q", lan)
		}
		seen[lan] = true
	}
	if proxy := config.ProxyDevice; proxy != "" {
		if !policy.ValidInterface(proxy) || seen[proxy] {
			return config, fmt.Errorf("invalid or repeated proxy device %q", proxy)
		}
		seen[proxy] = true
	}
	var networks []string
	for _, uplink := range config.Uplinks {
		if !networkName.MatchString(uplink.Network) || !policy.ValidInterface(uplink.Device) ||
			seen[uplink.Device] || slices.Contains(networks, uplink.Network) {
			return config, fmt.Errorf("invalid or repeated uplink %s/%s", uplink.Network, uplink.Device)
		}
		seen[uplink.Device] = true
		networks = append(networks, uplink.Network)
	}
	for _, device := range config.UnmanagedEgressDevices {
		if !policy.ValidInterface(device) || seen[device] {
			return config, fmt.Errorf("invalid or repeated unmanaged egress device %q", device)
		}
		seen[device] = true
	}
	prefixes, err := policy.Parse(config.LAN)
	if err != nil {
		return config, err
	}
	config.lan4 = policy.Elements(prefixes, 32)
	if config.lan4 == "" {
		return config, fmt.Errorf("OpenWrt requires protected LAN IPv4 source prefixes")
	}
	source, err := policy.ReadSource(config.Policy)
	if err != nil {
		return config, err
	}
	config.direct, err = policy.Parse(source.Networks)
	if err != nil {
		return config, err
	}
	// An external list is versioned in the policy file. Adding a LAN range
	// explicitly avoids silently widening what the physical WAN may send.
	if policy.Elements(config.direct, 32) == "" {
		return config, fmt.Errorf("OpenWrt requires approved IPv4 destinations")
	}
	return config, nil
}

func (c Config) find(network, device string) (Uplink, error) {
	for _, u := range c.Uplinks {
		if u.Network == network && u.Device == device {
			return u, nil
		}
	}
	return Uplink{}, fmt.Errorf("unconfigured OpenWrt uplink %s/%s", network, device)
}
