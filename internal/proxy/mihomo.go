package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"

	"clatch-gateway/internal/policy"

	"go.yaml.in/yaml/v3"
)

type Mihomo struct {
	TPROXYPort uint16
}

func ReadMihomo(config policy.Config) (Mihomo, error) {
	data, err := os.ReadFile(config.Proxy.Config)
	if err != nil {
		return Mihomo{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var settings map[string]any
	if err := decoder.Decode(&settings); err != nil || settings == nil {
		return Mihomo{}, fmt.Errorf("invalid private mihomo configuration")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Mihomo{}, fmt.Errorf("mihomo configuration must contain one document")
	}
	return validateMihomo(config, settings)
}

func validateMihomo(config policy.Config, settings map[string]any) (Mihomo, error) {
	if settings["routing-mark"] != 128 || settings["ipv6"] != false || settings["mode"] != "rule" {
		return Mihomo{}, fmt.Errorf("mihomo requires routing-mark=128, ipv6=false and mode=rule")
	}
	if !optionalZero(settings, "redir-port") || !optionalEmptyList(settings, "listeners") {
		return Mihomo{}, fmt.Errorf("additional mihomo capture listeners must be disabled")
	}
	iface, specified := settings["interface-name"]
	if (specified || config.IsTUN()) && iface != config.Interface {
		return Mihomo{}, fmt.Errorf("mihomo interface-name differs from the gateway interface")
	}
	dns, ok := settings["dns"].(map[string]any)
	if !ok || dns["enable"] != true || dns["enhanced-mode"] != "redir-host" {
		return Mihomo{}, fmt.Errorf("mihomo DNS requires enabled redir-host mode")
	}
	listen, _ := dns["listen"].(string)
	address, err := netip.ParseAddrPort(listen)
	if err != nil || !address.Addr().Is4() || address.Port() != config.Proxy.DNSPort ||
		(address.Addr().String() != config.Proxy.DNSAddress && !address.Addr().IsUnspecified()) {
		return Mihomo{}, fmt.Errorf("mihomo DNS listener differs from the approved endpoint")
	}
	if config.IsTUN() {
		if !optionalZero(settings, "tproxy-port") || dns["fake-ip-range"] != "172.31.255.1/30" {
			return Mihomo{}, fmt.Errorf("managed mihomo TUN requires disabled TPROXY and the fixed IPv4 TUN address")
		}
		return Mihomo{}, validateMihomoTUN(settings["tun"])
	}
	port, ok := settings["tproxy-port"].(int)
	if !ok || port < 1024 || port > 65535 {
		return Mihomo{}, fmt.Errorf("mihomo tproxy-port must be between 1024 and 65535")
	}
	if raw, exists := settings["tun"]; exists {
		tun, ok := raw.(map[string]any)
		enabled, specified := tun["enable"]
		if !ok || specified && enabled != false {
			return Mihomo{}, fmt.Errorf("mihomo TUN must be disabled during TPROXY")
		}
		for _, field := range []string{"auto-route", "auto-redirect"} {
			if _, exists := tun[field]; exists {
				return Mihomo{}, fmt.Errorf("mihomo TPROXY cannot include TUN automatic routing options")
			}
		}
	}
	return Mihomo{TPROXYPort: uint16(port)}, nil
}

func validateMihomoTUN(raw any) error {
	tun, ok := raw.(map[string]any)
	if !ok || tun["enable"] != true || tun["device"] != "jdn-tun" || tun["stack"] != "system" {
		return fmt.Errorf("unsupported mihomo TUN device or stack")
	}
	for key := range tun {
		switch key {
		case "enable", "device", "stack", "auto-route", "auto-redirect", "auto-detect-interface",
			"inet6-address", "mtu", "gso", "dns-mode", "dns-hijack":
		default:
			return fmt.Errorf("unsupported field in managed mihomo TUN")
		}
	}
	for _, option := range []string{"auto-route", "auto-redirect", "auto-detect-interface", "gso"} {
		if tun[option] != false {
			return fmt.Errorf("managed mihomo TUN requires disabled routing automation and offload")
		}
	}
	if tun["mtu"] != 1500 || tun["dns-mode"] != "disabled" ||
		!optionalEmptyList(tun, "inet6-address") || !optionalEmptyList(tun, "dns-hijack") {
		return fmt.Errorf("unsupported managed mihomo TUN MTU, DNS or IPv6 setting")
	}
	return nil
}

func optionalZero(settings map[string]any, key string) bool {
	value, exists := settings[key]
	return !exists || value == 0
}

func optionalEmptyList(settings map[string]any, key string) bool {
	value, exists := settings[key]
	list, ok := value.([]any)
	return !exists || ok && len(list) == 0
}
