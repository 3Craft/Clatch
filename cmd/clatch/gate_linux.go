//go:build linux

package main

import "clatch-gateway/internal/gateway"

func runGuard(args []string) (any, error) {
	if len(args) == 3 && args[0] == "ensure" {
		return gateway.Ensure(args[1], args[2])
	}
	if len(args) == 2 && args[0] == "verify" {
		return gateway.Verify(args[1])
	}
	return nil, errUsage
}
