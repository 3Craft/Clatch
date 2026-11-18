//go:build linux

package main

import (
	"fmt"
	"path/filepath"

	"clatch-gateway/internal/gateway"
)

func runLegacyGuard(args []string) (any, error) {
	options := map[string]string{"--config": "/etc/jdn-gateway/config.json"}
	action := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config", "--gate-interface", "--transaction-dir", "--whitelist-json", "--geoip":
			option := args[i]
			i++
			if i == len(args) {
				return nil, errUsage
			}
			options[option] = args[i]
		default:
			if action != "" {
				return nil, errUsage
			}
			action = args[i]
		}
	}
	config := options["--config"]
	switch action {
	case "ensure":
		return gateway.Ensure(config, options["--gate-interface"])
	case "verify":
		return gateway.Verify(config)
	case "native-policy":
		return gateway.InspectPolicy(config, options["--geoip"])
	case "native-tun-bind":
		return gateway.NativeBind(config, true)
	case "native-tun-unbind":
		return gateway.NativeBind(config, false)
	case "stage", "commit", "rollback":
		if options["--transaction-dir"] == "" {
			return nil, errUsage
		}
		directory, err := filepath.Abs(options["--transaction-dir"])
		if err != nil {
			return nil, err
		}
		return policyResult(action, config, directory, options["--whitelist-json"], options["--geoip"])
	default:
		return nil, fmt.Errorf("unknown gateway guard action %q", action)
	}
}
