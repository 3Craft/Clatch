package main

import (
	"fmt"
	"strings"

	"clatch-gateway/internal/openwrt"
)

func runOpenWrtCheck(args []string) (any, error) {
	options, err := readOptions("openwrt check", args, true)
	if err != nil {
		return nil, err
	}
	if !options.explicit {
		options.config = openwrt.DefaultConfigPath
	}
	cfg, err := openwrt.ReadConfig(options.config)
	data := map[string]any{}
	if err == nil {
		data["lan_devices"] = cfg.LANDevices
		data["lan"] = cfg.LAN
		data["uplinks"] = cfg.Uplinks
		data["policy"] = cfg.Policy
		data["direct_networks"] = len(cfg.DirectPrefixes())
		if cfg.ProxyDevice != "" {
			data["proxy_device"] = cfg.ProxyDevice
		}
		if len(cfg.UnmanagedEgressDevices) > 0 {
			data["unmanaged_egress_devices"] = cfg.UnmanagedEgressDevices
		}
	}
	var out strings.Builder
	if err == nil {
		fmt.Fprintln(&out, "OpenWrt configuration is valid")
	} else {
		fmt.Fprintln(&out, "OpenWrt configuration check failed")
	}
	fmt.Fprintf(&out, "Configuration  %s\n", options.config)
	if err == nil {
		fmt.Fprintf(&out, "LAN devices    %s\n", strings.Join(cfg.LANDevices, ", "))
		fmt.Fprintf(&out, "Policy         %s (%d direct networks)\n", cfg.Policy, len(cfg.DirectPrefixes()))
		for _, u := range cfg.Uplinks {
			fmt.Fprintf(&out, "Uplink         %s (%s)\n", u.Network, u.Device)
		}
	} else {
		fmt.Fprintf(&out, "Error          %v\n", err)
	}
	return checkReport(options, data, out.String(), err)
}
