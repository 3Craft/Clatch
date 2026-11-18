//go:build linux

package main

import (
	"fmt"
	"strconv"

	"clatch-gateway/internal/firewall"
	"clatch-gateway/internal/policy"
)

func runNFT(args []string) (any, error) {
	if (len(args) != 2 && len(args) != 3) || args[0] != "render" {
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
	var tunIndex uint64
	if len(args) == 3 {
		tunIndex, err = strconv.ParseUint(args[2], 10, 32)
		if err != nil {
			return nil, err
		}
	}
	rules, err := firewall.RenderGuard(config, approved, uint32(tunIndex))
	if err != nil {
		return nil, err
	}
	_, err = fmt.Print(rules)
	return nil, err
}
