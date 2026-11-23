//go:build linux

package openwrt

import (
	"fmt"
	"net/netip"

	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/policy"
)

const DefaultConfigPath = "/etc/clatch/openwrt.json"

// UplinkStatus describes the verification and counter state of one guarded WAN uplink.
type UplinkStatus struct {
	Network  string            `json:"network"`
	Device   string            `json:"device"`
	Verified bool              `json:"verified"`
	Link     *guard.LinkInfo   `json:"link,omitempty"`
	Stats    map[string]uint64 `json:"stats,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// StatusReport summarizes local OpenWrt Clatch configuration and uplink state.
type StatusReport struct {
	State                  string         `json:"state"`
	Config                 string         `json:"config"`
	Policy                 string         `json:"policy,omitempty"`
	DirectNetworks         int            `json:"direct_networks,omitempty"`
	LANDevices             []string       `json:"lan_devices,omitempty"`
	ProxyDevice            string         `json:"proxy_device,omitempty"`
	UnmanagedEgressDevices []string       `json:"unmanaged_egress_devices,omitempty"`
	Uplinks                []UplinkStatus `json:"uplinks,omitempty"`
	Issues                 []string       `json:"issues,omitempty"`
}

// DirectPrefixes returns the canonical direct IPv4 prefixes loaded from the policy file.
func (c Config) DirectPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, len(c.direct))
	copy(out, c.direct)
	return out
}

// LANPrefixes parses and returns the canonical protected LAN prefixes.
func (c Config) LANPrefixes() ([]netip.Prefix, error) {
	return policy.Parse(c.LAN)
}

// PolicyEntries builds the guard policy trie map matching WAN enforcement.
func (c Config) PolicyEntries() guard.Policy {
	entries := policy.Config{}.Entries(policy.Approved{Prefixes: c.direct})
	return entries
}

// Status collects configuration and per-uplink enforcement status for OpenWrt.
func Status(path string) (StatusReport, error) {
	report := StatusReport{Config: path, State: "unknown"}
	cfg, err := ReadConfig(path)
	if err != nil {
		report.Issues = append(report.Issues, "configuration: "+err.Error())
		return report, err
	}
	report.State = "healthy"
	report.Policy = cfg.Policy
	report.DirectNetworks = len(cfg.direct)
	report.LANDevices = cfg.LANDevices
	report.ProxyDevice = cfg.ProxyDevice
	report.UnmanagedEgressDevices = cfg.UnmanagedEgressDevices
	for _, u := range cfg.Uplinks {
		item := UplinkStatus{Network: u.Network, Device: u.Device}
		if err := checkNetwork(u); err != nil {
			item.Error = err.Error()
			report.Issues = append(report.Issues, fmt.Sprintf("%s (%s): %v", u.Network, u.Device, err))
			report.Uplinks = append(report.Uplinks, item)
			continue
		}
		info, err := verifyUplink(cfg, u)
		if err != nil {
			item.Error = err.Error()
			report.Issues = append(report.Issues, fmt.Sprintf("%s (%s): %v", u.Network, u.Device, err))
		} else {
			item.Verified = true
			item.Link = &info
			if pins, pinErr := pinsFor(u.Device); pinErr == nil {
				if stats, statsErr := guard.Stats(pins); statsErr == nil {
					item.Stats = stats
				}
			}
		}
		report.Uplinks = append(report.Uplinks, item)
	}
	if len(report.Issues) > 0 {
		report.State = "degraded"
	}
	return report, nil
}

// UplinkStats reads per-CPU TCX counters for each configured OpenWrt uplink.
func UplinkStats(path string) (map[string]map[string]uint64, error) {
	cfg, err := ReadConfig(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]uint64, len(cfg.Uplinks))
	for _, u := range cfg.Uplinks {
		pins, err := pinsFor(u.Device)
		if err != nil {
			return nil, fmt.Errorf("uplink %s (%s): %w", u.Network, u.Device, err)
		}
		counters, err := guard.Stats(pins)
		if err != nil {
			return nil, fmt.Errorf("uplink %s (%s): %w", u.Network, u.Device, err)
		}
		out[u.Network+"/"+u.Device] = counters
	}
	return out, nil
}
