//go:build linux

package main

import (
	"path/filepath"

	"clatch-gateway/internal/gateway"
)

func runPolicy(args []string) (any, error) {
	var source string
	switch {
	case len(args) == 4 && args[0] == "stage":
		source = args[3]
	case len(args) == 3 && (args[0] == "commit" || args[0] == "rollback"):
	default:
		return nil, errUsage
	}
	return policyResult(args[0], args[1], args[2], source, "")
}

func policyResult(action, config, directory, source, geoIP string) (any, error) {
	status, err := gateway.PolicyTransaction(action, config, directory, source, geoIP)
	if err != nil {
		return nil, err
	}
	return map[string]string{"state": status, "transaction": filepath.Join(directory, "transaction.json")}, nil
}
