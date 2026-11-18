//go:build linux

package main

import (
	"fmt"

	"clatch-gateway/internal/policy"
)

func runConfig(args []string) (any, error) {
	if len(args) != 2 || args[0] != "check" {
		return nil, errUsage
	}
	config, err := policy.ReadConfig(args[1])
	if err != nil {
		return nil, err
	}
	approved, err := config.ReadApproved()
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
	entries := config.Entries(approved)
	if len(entries) > 20000 {
		return nil, fmt.Errorf("policy plus LAN and diagnostic exceptions exceeds TCX capacity")
	}
	return map[string]any{
		"interface": config.Interface, "backend": backend, "mode": mode,
		"network_sha256": approved.NetworkSHA256, "networks": len(approved.Prefixes),
		"policy_entries": len(entries),
	}, nil
}
