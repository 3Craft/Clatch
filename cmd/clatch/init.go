package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"clatch-gateway/internal/openwrt"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

type initProfileDoc struct {
	Schema     int           `json:"schema"`
	Name       string        `json:"name,omitempty"`
	Interface  string        `json:"interface"`
	Address    string        `json:"address"`
	Gateway    string        `json:"gateway"`
	LAN        []string      `json:"lan"`
	PublicIPv6 bool          `json:"public_ipv6"`
	NativeMode string        `json:"native_mode,omitempty"`
	Proxy      *policy.Proxy `json:"proxy,omitempty"`
}

func runInit(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errUsage
	}
	switch args[0] {
	case "profile":
		return runInitProfile(args[1:])
	case "policy":
		return runInitPolicy(args[1:])
	case "health":
		return runInitHealth(args[1:])
	case "openwrt":
		return runInitOpenWrt(args[1:])
	default:
		return nil, usageError("unknown init target %q (expected profile, policy, health, or openwrt)", args[0])
	}
}

func runInitProfile(args []string) (any, error) {
	var options inspectionOptions
	flags := options.flags("init profile")
	backend := flags.String("backend", "xray-core", "proxy backend: xray-core, mihomo, v2ray-core, or v2raya")
	mode := flags.String("mode", "tproxy", "interception mode: tproxy or tun")
	name := flags.String("name", "", "gateway profile name")
	iface := flags.String("interface", "", "egress Ethernet interface")
	address := flags.String("address", "", "static IPv4 host CIDR")
	gw := flags.String("gateway", "", "upstream IPv4 gateway")
	output := flags.String("output", "", "write generated JSON to path")
	force := flags.Bool("force", false, "overwrite existing output file")
	var lans []string
	flags.Func("lan", "protected LAN IPv4 prefix (repeatable)", func(v string) error {
		for item := range strings.SplitSeq(v, ",") {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				lans = append(lans, trimmed)
			}
		}
		return nil
	})
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if err := options.resolveFormat(flags); err != nil {
		return nil, err
	}

	detectedIface, detectedAddr, detectedGW, detectedLAN := detectHostNetwork()
	if *iface == "" {
		*iface = detectedIface
	}
	if *address == "" {
		*address = detectedAddr
	}
	if *gw == "" {
		*gw = detectedGW
	}
	if len(lans) == 0 {
		if detectedLAN != "" {
			lans = []string{detectedLAN}
		} else {
			lans = []string{"192.0.2.0/24"}
		}
	}
	if *iface == "" {
		*iface = "eth0"
	}
	if *address == "" {
		*address = "192.0.2.10/24"
	}
	if *gw == "" {
		*gw = "192.0.2.1"
	}
	if *name == "" {
		*name = fmt.Sprintf("clatch-%s-gateway", *backend)
	}

	doc := initProfileDoc{
		Schema:     1,
		Name:       *name,
		Interface:  *iface,
		Address:    *address,
		Gateway:    *gw,
		LAN:        lans,
		PublicIPv6: false,
	}

	switch *backend {
	case "v2raya":
		if *mode != "tproxy" && *mode != "tun" {
			return nil, usageError("invalid --mode %q for v2raya (expected tproxy or tun)", *mode)
		}
		doc.NativeMode = *mode
	case "xray-core":
		if *mode != "tproxy" {
			return nil, usageError("xray-core only supports --mode tproxy")
		}
		doc.Proxy = &policy.Proxy{
			Kind:         "xray-core",
			Mode:         "tproxy",
			Service:      "xray.service",
			Binary:       "/usr/local/bin/xray",
			Config:       "/usr/local/etc/xray/config.json",
			PolicySource: "/root/gateway-policy.json",
			DNSAddress:   "127.0.0.1",
			DNSPort:      53,
		}
	case "v2ray-core":
		if *mode != "tproxy" {
			return nil, usageError("v2ray-core only supports --mode tproxy")
		}
		doc.Proxy = &policy.Proxy{
			Kind:         "v2ray-core",
			Mode:         "tproxy",
			Service:      "v2ray.service",
			Binary:       "/usr/local/bin/v2ray",
			Config:       "/usr/local/etc/v2ray/config.json",
			PolicySource: "/root/gateway-policy.json",
			DNSAddress:   "127.0.0.1",
			DNSPort:      53,
		}
	case "mihomo":
		if *mode != "tproxy" && *mode != "tun" {
			return nil, usageError("invalid --mode %q for mihomo (expected tproxy or tun)", *mode)
		}
		doc.Proxy = &policy.Proxy{
			Kind:         "mihomo",
			Mode:         *mode,
			Service:      "mihomo.service",
			Binary:       "/usr/local/bin/mihomo",
			Config:       "/etc/mihomo/config.yaml",
			PolicySource: "/root/gateway-policy.json",
			DNSAddress:   "127.0.0.1",
			DNSPort:      53,
		}
	default:
		return nil, usageError("unknown --backend %q (expected xray-core, mihomo, v2ray-core, or v2raya)", *backend)
	}

	next := []string{
		fmt.Sprintf("clatch doctor --profile %s", fallbackPath(*output, "/root/gateway-profile.json")),
		fmt.Sprintf("clatch install plan %s", fallbackPath(*output, "/root/gateway-profile.json")),
	}
	return writeInitOutput("install-profile", doc, *output, *force, options.json, next)
}

func runInitPolicy(args []string) (any, error) {
	var options inspectionOptions
	flags := options.flags("init policy")
	output := flags.String("output", "", "write generated JSON to path")
	force := flags.Bool("force", false, "overwrite existing output file")
	var networks []string
	flags.Func("networks", "direct IPv4 CIDR(s), comma-separated or repeatable", func(v string) error {
		for item := range strings.SplitSeq(v, ",") {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				networks = append(networks, trimmed)
			}
		}
		return nil
	})
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if err := options.resolveFormat(flags); err != nil {
		return nil, err
	}
	if len(networks) == 0 {
		_, _, _, detectedLAN := detectHostNetwork()
		if detectedLAN != "" {
			networks = append(networks, detectedLAN)
		} else {
			networks = append(networks, "192.0.2.0/24")
		}
		networks = append(networks, "198.51.100.10/32")
	}
	prefixes, err := policy.Parse(networks)
	if err != nil {
		return nil, usageError("invalid --networks: %v", err)
	}
	doc := policy.Source{
		Schema:   1,
		Networks: policy.Strings(prefixes),
		Metadata: map[string]any{
			"note": "Include your LAN CIDR(s) and every upstream proxy server IP/CIDR.",
		},
	}
	return writeInitOutput("policy-source", doc, *output, *force, options.json, nil)
}

func runInitHealth(args []string) (any, error) {
	var options inspectionOptions
	flags := options.flags("init health")
	dnsAddr := flags.String("dns", "", "IPv4 resolver address or address:port")
	conntrack := flags.Bool("conntrack", false, "enable conntrack verification")
	emptyAAAA := flags.Bool("expect-empty-aaaa", false, "require empty AAAA replies")
	directURL := flags.String("direct-url", "", "custom direct HTTPS probe URL")
	proxyURL := flags.String("proxy-url", "", "custom proxy exit-IP HTTPS probe URL")
	output := flags.String("output", "", "write generated JSON to path")
	force := flags.Bool("force", false, "overwrite existing output file")
	var exits []string
	flags.Func("expected-exit", "expected proxy exit IPv4 address (repeatable)", func(v string) error {
		addr, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil || !addr.Is4() {
			return fmt.Errorf("invalid IPv4 address %q", v)
		}
		exits = append(exits, addr.String())
		return nil
	})
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if err := options.resolveFormat(flags); err != nil {
		return nil, err
	}
	if len(exits) == 0 {
		exits = []string{"203.0.113.10"}
	}
	doc := map[string]any{
		"expected_exits": exits,
		"conntrack":      *conntrack,
	}
	if *dnsAddr != "" {
		doc["dns"] = *dnsAddr
	}
	if *emptyAAAA {
		doc["expect_empty_aaaa"] = true
	}
	if *directURL != "" {
		doc["direct_url"] = *directURL
	}
	if *proxyURL != "" {
		doc["proxy_url"] = *proxyURL
	}
	return writeInitOutput("health", doc, *output, *force, options.json, []string{"clatch health"})
}

func runInitOpenWrt(args []string) (any, error) {
	var options inspectionOptions
	flags := options.flags("init openwrt")
	policyPath := flags.String("policy", "/etc/clatch/policy.json", "approved policy file path")
	output := flags.String("output", "", "write generated JSON to path")
	force := flags.Bool("force", false, "overwrite existing output file")
	var lanDevices, lans []string
	var uplinks []openwrt.Uplink
	flags.Func("lan-device", "LAN bridge/device name (repeatable)", func(v string) error {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			lanDevices = append(lanDevices, trimmed)
		}
		return nil
	})
	flags.Func("lan", "protected LAN IPv4 prefix (repeatable)", func(v string) error {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			lans = append(lans, trimmed)
		}
		return nil
	})
	flags.Func("uplink", "logical:device uplink mapping, e.g. wan:eth1 (repeatable)", func(v string) error {
		network, device, ok := strings.Cut(strings.TrimSpace(v), ":")
		if !ok || network == "" || device == "" {
			return fmt.Errorf("expected NETWORK:DEVICE (for example wan:eth1)")
		}
		uplinks = append(uplinks, openwrt.Uplink{Network: network, Device: device})
		return nil
	})
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if err := options.resolveFormat(flags); err != nil {
		return nil, err
	}
	if len(lanDevices) == 0 {
		lanDevices = []string{"br-lan"}
	}
	if len(lans) == 0 {
		lans = []string{"192.168.1.0/24"}
	}
	if len(uplinks) == 0 {
		uplinks = []openwrt.Uplink{{Network: "wan", Device: "eth1"}}
	}
	doc := openwrt.Config{
		Schema:     1,
		LANDevices: lanDevices,
		LAN:        lans,
		Uplinks:    uplinks,
		Policy:     *policyPath,
	}
	return writeInitOutput("openwrt", doc, *output, *force, options.json, []string{
		fmt.Sprintf("clatch openwrt check --config %s", fallbackPath(*output, openwrt.DefaultConfigPath)),
		fmt.Sprintf("clatch openwrt install --config %s", fallbackPath(*output, openwrt.DefaultConfigPath)),
	})
}

func writeInitOutput(schemaName string, doc any, output string, force, asJSON bool, nextSteps []string) (any, error) {
	pretty, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	pretty = append(pretty, '\n')
	if output == "" {
		return inspection{
			value: doc,
			text:  string(pretty),
		}, nil
	}
	if !force {
		if _, err := os.Lstat(output); err == nil {
			return nil, fmt.Errorf("refusing to overwrite existing file %s (pass --force to replace)", output)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return nil, err
	}
	if err := system.WriteAtomic(output, pretty, 0600); err != nil {
		return nil, err
	}
	payload := map[string]any{
		"written":    true,
		"path":       output,
		"schema":     schemaName,
		"next_steps": nextSteps,
	}
	var out strings.Builder
	fmt.Fprintf(&out, "Wrote %s template to %s\n", schemaName, output)
	for i, step := range nextSteps {
		if i == 0 {
			fmt.Fprintf(&out, "Next step      %s\n", step)
		} else {
			fmt.Fprintf(&out, "               %s\n", step)
		}
	}
	res := inspection{value: payload}
	if !asJSON {
		res.text = out.String()
	}
	return res, nil
}

func fallbackPath(path, def string) string {
	if path != "" {
		return path
	}
	return def
}
