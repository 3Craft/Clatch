//go:build linux

package main

import (
	"fmt"
	"strings"

	"clatch-gateway/internal/gateway"
)

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
		return checkReport(options, result, formatGuardVerify(options.config, result, err), err)
	}
	return nil, errUsage
}

func formatGuardVerify(path string, result map[string]any, err error) string {
	var out strings.Builder
	if err == nil {
		fmt.Fprintf(&out, "Guard verification passed\n")
	} else {
		fmt.Fprintf(&out, "Guard verification failed\n")
	}
	fmt.Fprintf(&out, "Configuration  %s\n", path)
	if sha, ok := result["network_sha256"].(string); ok && sha != "" {
		short := sha
		if len(short) > 12 {
			short = short[:12]
		}
		fmt.Fprintf(&out, "Policy SHA     %s\n", short)
	}
	if linkID, ok := result["link_id"]; ok {
		fmt.Fprintf(&out, "TCX            link=%v prog=%v map=%v ifindex=%v\n",
			linkID, result["program_id"], result["map_id"], result["ifindex"])
	}
	if tun, ok := result["trusted_tun_ifindex"].(uint32); ok && tun > 0 {
		fmt.Fprintf(&out, "Trusted TUN    ifindex=%d\n", tun)
	}
	if stats, ok := result["stats"].(map[string]uint64); ok && len(stats) > 0 {
		allow, deny := summarizeCounters(stats)
		fmt.Fprintf(&out, "Counters       allow=%d deny=%d\n", allow, deny)
	}
	if err != nil {
		fmt.Fprintf(&out, "Error          %v\n", err)
	}
	return out.String()
}

func summarizeCounters(stats map[string]uint64) (allow, deny uint64) {
	for k, v := range stats {
		if strings.HasPrefix(k, "allow_") {
			allow += v
		} else if strings.HasPrefix(k, "deny_") {
			deny += v
		}
	}
	return allow, deny
}
