package main

import (
	"fmt"
	"strings"

	"clatch-gateway/internal/policy"
)

func runConfig(args []string) (any, error) {
	if len(args) == 0 || args[0] != "check" {
		return nil, errUsage
	}
	options, err := readOptions("config check", args[1:], true)
	if err != nil {
		return nil, err
	}
	result, err := checkConfig(options.config)
	return checkReport(options, result, formatConfigCheck(options.config, result, err), err)
}

func formatConfigCheck(path string, result map[string]any, err error) string {
	var out strings.Builder
	if err == nil {
		fmt.Fprintf(&out, "Configuration is valid\n")
	} else {
		fmt.Fprintf(&out, "Configuration check failed\n")
	}
	fmt.Fprintf(&out, "Configuration  %s\n", path)
	if iface, ok := result["interface"].(string); ok && iface != "" {
		fmt.Fprintf(&out, "Interface      %s\n", iface)
	}
	if backend, ok := result["backend"].(string); ok && backend != "" {
		mode, _ := result["mode"].(string)
		fmt.Fprintf(&out, "Proxy          %s (%s)\n", backend, mode)
	}
	if networks, ok := result["networks"].(int); ok {
		entries, _ := result["policy_entries"].(int)
		fmt.Fprintf(&out, "Policy         %d direct networks (%d / 20000 TCX entries)\n", networks, entries)
	}
	if sha, ok := result["network_sha256"].(string); ok && sha != "" {
		short := sha
		if len(short) > 12 {
			short = short[:12]
		}
		fmt.Fprintf(&out, "Policy SHA     %s\n", short)
	}
	if err != nil {
		fmt.Fprintf(&out, "Error          %v\n", err)
	}
	return out.String()
}

func checkConfig(path string) (map[string]any, error) {
	config, err := policy.ReadConfig(path)
	if err != nil {
		return nil, err
	}
	backend := config.NativeService
	if config.Proxy != nil {
		backend = config.Proxy.Kind
	}
	mode := "tproxy"
	if config.IsTUN() {
		mode = "tun"
	}
	result := map[string]any{"interface": config.Interface, "backend": backend, "mode": mode}
	approved, err := config.ReadApproved()
	if err != nil {
		return result, err
	}
	entries := config.Entries(approved)
	result["network_sha256"], result["networks"] = approved.NetworkSHA256, len(approved.Prefixes)
	result["policy_entries"] = len(entries)
	if len(entries) > 20000 {
		return result, fmt.Errorf("policy plus LAN and diagnostic exceptions exceeds TCX capacity")
	}
	return result, nil
}
