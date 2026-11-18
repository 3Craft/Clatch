//go:build linux

package main

import (
	"strconv"

	"clatch-gateway/internal/capture"
)

func runCapture(args []string) (any, error) {
	if len(args) == 1 && args[0] == "stop" {
		return nil, capture.StopTPROXY()
	}
	if (len(args) == 2 || len(args) == 3) && args[0] == "start" {
		var port uint64
		if len(args) == 3 {
			var err error
			port, err = strconv.ParseUint(args[2], 10, 16)
			if err != nil || port < 1024 {
				return nil, errUsage
			}
		}
		return capture.StartTPROXY(args[1], uint16(port))
	}
	return nil, errUsage
}
