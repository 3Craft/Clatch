//go:build linux

package main

import (
	"fmt"

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
	return checkReport(options, result, err)
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
