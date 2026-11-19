//go:build linux

package main

import (
	"flag"

	"clatch-gateway/internal/gateway"
	"clatch-gateway/internal/native"
	"clatch-gateway/internal/policy"
)

func runNative(args []string) (any, error) {
	if len(args) > 0 && args[0] == "hook" {
		return runNativeHook(args[1:])
	}
	if len(args) != 2 {
		return nil, errUsage
	}
	switch args[0] {
	case "inspect":
		config, err := policy.ReadConfig(args[1])
		if err != nil {
			return nil, err
		}
		return native.Inspect(config)
	case "bind":
		return gateway.NativeBind(args[1], true)
	case "unbind":
		return gateway.NativeBind(args[1], false)
	default:
		return nil, errUsage
	}
}

func runNativeHook(args []string) (any, error) {
	flags := flag.NewFlagSet("native hook", flag.ContinueOnError)
	stage := flags.String("stage", "", "v2rayA transparent proxy lifecycle stage")
	kind := flags.String("transparent-type", "", "transparent proxy mode")
	check := flags.Bool("check", false, "validate the DNS rules without changing them")
	confdir := flags.String("v2raya-confdir", "", "v2rayA configuration directory")
	config := flags.String("config", policy.DefaultConfigPath, "approved guard configuration")
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if flags.NArg() != 0 {
		return nil, errUsage
	}
	return gateway.NativeHook(*config, *confdir, *stage, *kind, *check)
}
