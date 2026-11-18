//go:build linux

package main

import (
	"strconv"

	"clatch-gateway/internal/openwrt"
)

func runOpenWrt(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errUsage
	}
	switch args[0] {
	case "prepare":
		if len(args) == 4 {
			return openwrt.Prepare(args[1], args[2], args[3])
		}
	case "verify":
		if len(args) == 4 {
			return openwrt.Verify(args[1], args[2], args[3])
		}
	case "tproxy-start":
		if len(args) == 3 {
			port, err := strconv.ParseUint(args[2], 10, 16)
			if err != nil {
				return nil, errUsage
			}
			return nil, openwrt.StartTPROXY(args[1], uint16(port))
		}
	case "tproxy-stop":
		if len(args) == 1 {
			return nil, openwrt.StopTPROXY()
		}
	}
	return nil, errUsage
}
