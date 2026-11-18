//go:build linux

package main

import "clatch-gateway/internal/openwrt"

func runOpenWrt(args []string) (any, error) {
	if len(args) != 4 {
		return nil, errUsage
	}
	switch args[0] {
	case "prepare":
		return openwrt.Prepare(args[1], args[2], args[3])
	case "verify":
		return openwrt.Verify(args[1], args[2], args[3])
	default:
		return nil, errUsage
	}
}
