//go:build linux

package openwrt

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"clatch-gateway/internal/capture"
	"clatch-gateway/internal/firewall"
	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

const (
	table       = "clatch_routed_wan"
	lock        = "/var/lock/clatch-openwrt.lock"
	fingerprint = "/var/run/clatch-openwrt-nft.sha256"
)

// WAN never grants the traditional single-arm diagnostic exception.
var wanSettings = guard.Settings{DiagnosticUID: 65533}

func Prepare(path, logical, physical string) (guard.LinkInfo, error) {
	cfg, err := ReadConfig(path)
	if err != nil {
		return guard.LinkInfo{}, err
	}
	uplink, err := cfg.find(logical, physical)
	if err != nil {
		return guard.LinkInfo{}, err
	}
	var status guard.LinkInfo
	err = system.WithLock(lock, func() error {
		if err := checkNetwork(uplink); err != nil {
			return err
		}
		if err := system.MountBPF(); err != nil {
			return err
		}
		// Install the independent guard before authorizing the protocol to
		// publish a WAN address, route or DHCP lease.
		if err := firewall.ApplyTable(table, cfg.rules(), "", fingerprint); err != nil {
			return err
		}
		pins, err := pinsFor(uplink.Device)
		if err != nil {
			return err
		}
		entries := policy.Config{}.Entries(policy.Approved{Prefixes: cfg.direct})
		if _, err := os.Lstat(filepath.Join(pins, "link")); errors.Is(err, os.ErrNotExist) {
			if _, err := guard.AttachWAN(uplink.Device, "-", pins, entries, wanSettings); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		status, err = verifyUplink(cfg, uplink)
		return err
	})
	return status, err
}

func Verify(path, logical, physical string) (guard.LinkInfo, error) {
	cfg, err := ReadConfig(path)
	if err != nil {
		return guard.LinkInfo{}, err
	}
	uplink, err := cfg.find(logical, physical)
	if err != nil {
		return guard.LinkInfo{}, err
	}
	var status guard.LinkInfo
	err = system.WithLock(lock, func() error {
		if err := checkNetwork(uplink); err != nil {
			return err
		}
		status, err = verifyUplink(cfg, uplink)
		return err
	})
	return status, err
}

func StartTPROXY(path string, port uint16) error {
	if port < 1024 {
		return fmt.Errorf("TPROXY port must be 1024 or higher")
	}
	cfg, err := ReadConfig(path)
	if err != nil {
		return err
	}
	if cfg.ProxyDevice != "" {
		return fmt.Errorf("TPROXY and a TUN device cannot share the same OpenWrt profile")
	}
	return system.WithLock(lock, func() error {
		for _, uplink := range cfg.Uplinks {
			if err := checkNetwork(uplink); err != nil {
				return err
			}
			if _, err := verifyUplink(cfg, uplink); err != nil {
				return err
			}
		}
		return capture.StartRoutedTPROXY(path, port, quoteDevices(cfg.LANDevices), cfg.lan4, policy.Elements(cfg.direct, 32))
	})
}

func StopTPROXY() error {
	return system.WithLock(lock, capture.StopRoutedTPROXY)
}

func verifyUplink(cfg Config, uplink Uplink) (guard.LinkInfo, error) {
	pins, err := pinsFor(uplink.Device)
	if err != nil {
		return guard.LinkInfo{}, err
	}
	status, err := guard.VerifyWAN(uplink.Device, pins)
	if err != nil {
		return guard.LinkInfo{}, err
	}
	entries := policy.Config{}.Entries(policy.Approved{Prefixes: cfg.direct})
	if _, err := guard.CheckPolicy(pins, entries, wanSettings); err != nil {
		return guard.LinkInfo{}, err
	}
	if err := firewall.VerifyTable(table, cfg.rules(), fingerprint); err != nil {
		return guard.LinkInfo{}, err
	}
	return status, nil
}

func pinsFor(iface string) (string, error) {
	device, err := net.InterfaceByName(iface)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("/sys/fs/bpf/clatch-wan-%s-%d", iface, device.Index), nil
}

func checkNetwork(uplink Uplink) error {
	proto, err := system.Command("", "uci", "-q", "get", "network."+uplink.Network+".proto")
	if err != nil {
		return err
	}
	switch strings.TrimSpace(string(proto)) {
	case "clatch_dhcp", "clatch_static":
	default:
		return fmt.Errorf("uplink %s must run Clatch's pre-address protocol hook", uplink.Network)
	}
	configured, err := system.Command("", "uci", "-q", "get", "network."+uplink.Network+".device")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(configured)) != uplink.Device {
		return fmt.Errorf("uplink %s must use configured device %s", uplink.Network, uplink.Device)
	}
	filter, err := system.Command("", "uci", "show", "firewall")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(filter), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && (strings.HasSuffix(key, ".flow_offloading") ||
			strings.HasSuffix(key, ".flow_offloading_hw")) &&
			strings.Trim(value, "'\"") != "0" {
			return fmt.Errorf("disable flow offloading before bringing up a guarded uplink")
		}
	}
	kernel, err := system.Command("", "nft", "--json", "list", "ruleset")
	if err != nil {
		return err
	}
	var nft struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(kernel, &nft); err != nil {
		return err
	}
	for _, object := range nft.Objects {
		if _, found := object["flowtable"]; found {
			return fmt.Errorf("active kernel flowtable bypasses the guarded routing path")
		}
	}
	if status, err := system.Command("", "ubus", "call", "service", "list", `{"name":"bridger"}`); err != nil {
		return err
	} else if strings.Contains(string(status), `"running": true`) || strings.Contains(string(status), `"running":true`) {
		return fmt.Errorf("bridger acceleration bypasses the guarded routing path")
	}
	device, err := system.Command("", "ip", "-j", "-details", "link", "show", "dev", uplink.Device)
	if err != nil {
		return err
	}
	var links []struct {
		Type   string          `json:"link_type"`
		Master string          `json:"master"`
		XDP    json.RawMessage `json:"xdp"`
	}
	if err := json.Unmarshal(device, &links); err != nil {
		return err
	}
	if len(links) != 1 || links[0].Type != "ether" || links[0].Master != "" || len(links[0].XDP) != 0 {
		return fmt.Errorf("guarded uplink must use standalone Ethernet without XDP")
	}
	queue, err := system.Command("", "tc", "-j", "filter", "show", "dev", uplink.Device, "egress")
	if err != nil {
		return err
	}
	var filters []json.RawMessage
	if err := json.Unmarshal(queue, &filters); err != nil {
		return err
	}
	if len(filters) != 0 {
		return fmt.Errorf("unreviewed TC egress filter on %s", uplink.Device)
	}
	return nil
}

func quoteDevices(list []string) string {
	quoted := make([]string, 0, len(list))
	for _, dev := range list {
		quoted = append(quoted, fmt.Sprintf("%q", dev))
	}
	return strings.Join(quoted, ", ")
}

func (c Config) rules() string {
	wan := make([]string, 0, len(c.Uplinks))
	for _, u := range c.Uplinks {
		wan = append(wan, u.Device)
	}
	local := append([]string{"lo"}, c.LANDevices...)
	local = append(local, c.UnmanagedEgressDevices...)
	if c.ProxyDevice != "" {
		local = append(local, c.ProxyDevice)
	}
	return fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
 set wan { type ifname; elements = { %[2]s }; }
 set lan { type ifname; elements = { %[3]s }; }
 set local_devices { type ifname; elements = { %[4]s }; }
 set lan4 { type ipv4_addr; flags interval; elements = { %[5]s }; }
 set direct4 { type ipv4_addr; flags interval; elements = { %[6]s }; }
 chain pre_snat {
  type filter hook forward priority -10; policy accept;
  oifname @wan iifname @lan ip saddr @lan4 ip daddr @direct4 counter accept
  oifname @wan counter drop
 }
 chain physical_egress {
  type filter hook postrouting priority 110; policy drop;
  oifname @local_devices accept
  oifname @wan meta iif 0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 counter accept
  oifname @wan ip daddr 255.255.255.255 counter drop
  oifname @wan ip daddr @direct4 counter accept
  counter drop
 }
}
`, table, quoteDevices(wan), quoteDevices(c.LANDevices), quoteDevices(local), c.lan4, policy.Elements(c.direct, 32))
}
