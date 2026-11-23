//go:build linux

package main

import (
	"fmt"
	"sort"
	"strings"

	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/openwrt"
	"clatch-gateway/internal/policy"
)

type statsReport struct {
	Mode       string                       `json:"mode"`
	Config     string                       `json:"config"`
	Interface  string                       `json:"interface,omitempty"`
	Pins       string                       `json:"pins,omitempty"`
	AllowTotal uint64                       `json:"allow_total"`
	DenyTotal  uint64                       `json:"deny_total"`
	Counters   map[string]uint64            `json:"counters,omitempty"`
	Uplinks    map[string]map[string]uint64 `json:"uplinks,omitempty"`
}

var counterOrder = []string{
	"allow_direct", "allow_return", "allow_diagnostic", "allow_arp", "allow_ndp",
	"deny_destination", "deny_return", "deny_parse", "deny_ipv6", "deny_policy",
}

func runStats(args []string) (any, error) {
	var options inspectionOptions
	var openwrtPath string
	flags := options.flags("stats")
	flags.StringVar(&openwrtPath, "openwrt", "", "OpenWrt gateway configuration file")
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if err := options.resolve(flags, ""); err != nil {
		return nil, err
	}
	if openwrtPath != "" && options.explicit {
		return nil, usageError("use either --config or --openwrt, not both")
	}

	var report statsReport
	if openwrtPath != "" {
		uplinks, err := openwrt.UplinkStats(openwrtPath)
		if err != nil {
			return nil, err
		}
		var allowTotal, denyTotal uint64
		for _, counters := range uplinks {
			a, d := summarizeCounters(counters)
			allowTotal += a
			denyTotal += d
		}
		report = statsReport{
			Mode:       "openwrt",
			Config:     openwrtPath,
			AllowTotal: allowTotal,
			DenyTotal:  denyTotal,
			Uplinks:    uplinks,
		}
	} else {
		cfg, err := policy.ReadConfig(options.config)
		if err != nil {
			return nil, err
		}
		counters, err := guard.Stats(cfg.Pins)
		if err != nil {
			return nil, err
		}
		allowTotal, denyTotal := summarizeCounters(counters)
		report = statsReport{
			Mode:       "debian",
			Config:     options.config,
			Interface:  cfg.Interface,
			Pins:       cfg.Pins,
			AllowTotal: allowTotal,
			DenyTotal:  denyTotal,
			Counters:   counters,
		}
	}

	res := inspection{value: report}
	if !options.json {
		res.text = report.text()
	}
	return res, nil
}

func (r statsReport) text() string {
	var out strings.Builder
	fmt.Fprintf(&out, "Clatch TCX counters (%s)\nConfiguration  %s\n", r.Mode, r.Config)
	if r.Interface != "" {
		fmt.Fprintf(&out, "Interface      %s\nPins           %s\n", r.Interface, r.Pins)
	}
	fmt.Fprintf(&out, "Summary        allow=%d  deny=%d\n", r.AllowTotal, r.DenyTotal)
	if len(r.Counters) > 0 {
		out.WriteString("\nCounters:\n")
		writeCountersTable(&out, r.Counters)
	}
	if len(r.Uplinks) > 0 {
		names := make([]string, 0, len(r.Uplinks))
		for k := range r.Uplinks {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(&out, "\nUplink %s:\n", name)
			writeCountersTable(&out, r.Uplinks[name])
		}
	}
	return out.String()
}

func writeCountersTable(out *strings.Builder, counters map[string]uint64) {
	for _, key := range counterOrder {
		if val, ok := counters[key]; ok {
			fmt.Fprintf(out, "  %-18s %d\n", key, val)
		}
	}
}
