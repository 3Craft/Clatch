//go:build linux

package main

import "clatch-gateway/internal/gateway"

func runGuard(args []string) (any, error) {
	if len(args) == 3 && args[0] == "ensure" {
		return gateway.Ensure(args[1], args[2])
	}
	if len(args) > 0 && args[0] == "verify" {
		options, err := readOptions("guard verify", args[1:], true)
		if err != nil {
			return nil, err
		}
		result, err := gateway.Verify(options.config)
		return checkReport(options, result, err)
	}
	return nil, errUsage
}
