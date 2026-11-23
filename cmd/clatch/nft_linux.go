//go:build linux

package main

import (
	"strconv"
	"strings"

	"clatch-gateway/internal/firewall"
	"clatch-gateway/internal/policy"
)

func runNFT(args []string) (any, error) {
	if len(args) == 0 || args[0] != "render" {
		return nil, errUsage
	}
	var options inspectionOptions
	flags := options.flags("nft render")
	var positional []string
	var flagArgs []string
	for i := 1; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flagArgs = append(flagArgs, args[i])
			if (args[i] == "--config" || args[i] == "-config" || args[i] == "--format" || args[i] == "-format") && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		positional = append(positional, args[i])
	}
	if err := flags.Parse(flagArgs); err != nil {
		return nil, usageError("%v", err)
	}
	if err := options.resolveFormat(flags); err != nil {
		return nil, err
	}
	if len(positional) != 1 && len(positional) != 2 {
		return nil, errUsage
	}
	configPath := positional[0]
	config, err := policy.ReadConfig(configPath)
	if err != nil {
		return nil, err
	}
	approved, err := config.ReadApproved()
	if err != nil {
		return nil, err
	}
	var tunIndex uint64
	if len(positional) == 2 {
		tunIndex, err = strconv.ParseUint(positional[1], 10, 32)
		if err != nil {
			return nil, usageError("invalid TUN ifindex %q", positional[1])
		}
	}
	rules, err := firewall.RenderGuard(config, approved, uint32(tunIndex))
	if err != nil {
		return nil, err
	}
	res := inspection{
		value: map[string]any{
			"config":         configPath,
			"tun_ifindex":    uint32(tunIndex),
			"network_sha256": approved.NetworkSHA256,
			"rules":          rules,
		},
	}
	if !options.json {
		res.text = rules
	}
	return res, nil
}
