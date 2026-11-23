//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"clatch-gateway/internal/health"
	"clatch-gateway/internal/policy"
)

func runHealth(args []string) (any, error) {
	var request health.Request
	var options inspectionOptions
	flags := options.flags("health")
	flags.StringVar(&request.DirectURL, "direct-url", "https://www.baidu.com/", "direct application probe")
	flags.StringVar(&request.ProxyURL, "proxy-url", "https://ip.fm/myip", "application probe that returns the proxy exit address")
	flags.BoolVar(&request.EmptyAAAA, "expect-empty-aaaa", false, "require a successful empty IPv6 DNS answer")
	flags.BoolVar(&request.Marks, "conntrack", false, "check the tracked HTTPS flows on this gateway")
	flags.Func("dns", "IPv4 resolver address or address:port", func(value string) error {
		address, err := health.ParseResolver(value)
		request.Resolver = address
		return err
	})
	flags.Func("expected-exit", "approved IPv4 exit address, repeatable", func(value string) error {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			return fmt.Errorf("invalid IPv4 proxy exit address")
		}
		request.Exits = append(request.Exits, address)
		return nil
	})
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if err := options.resolve(flags, ""); err != nil {
		return nil, err
	}
	request.ConfigPath = options.config
	defaults, err := health.ReadDefaults(options.config)
	if err != nil {
		return failedHealth(options, request, err)
	}
	specified := make(map[string]bool)
	flags.Visit(func(flag *flag.Flag) { specified[flag.Name] = true })
	if !specified["conntrack"] {
		request.Marks = defaults.Conntrack
	}
	if !specified["expect-empty-aaaa"] {
		request.EmptyAAAA = defaults.EmptyAAAA
	}
	if !specified["direct-url"] && defaults.DirectURL != "" {
		request.DirectURL = defaults.DirectURL
	}
	if !specified["proxy-url"] && defaults.ProxyURL != "" {
		request.ProxyURL = defaults.ProxyURL
	}
	if len(defaults.DNSProbes) > 0 {
		request.DNSProbes = defaults.DNSProbes
	}
	if len(request.Exits) == 0 {
		request.Exits = defaults.ExpectedExits
	}
	if !request.Resolver.IsValid() && defaults.DNS != "" {
		request.Resolver, _ = health.ParseResolver(defaults.DNS)
	}
	if options.explicit || !request.Resolver.IsValid() {
		config, err := policy.ReadConfig(options.config)
		if err != nil && (options.explicit || !errors.Is(err, os.ErrNotExist)) {
			return failedHealth(options, request, err)
		}
		if err == nil && !request.Resolver.IsValid() {
			request.Resolver = health.LocalResolver(config)
		}
	}
	report, err := health.Check(context.Background(), request)
	res := inspection{value: report}
	if !options.json {
		res.text = formatHealthReport(report)
	}
	return res, err
}

func failedHealth(options inspectionOptions, request health.Request, err error) (inspection, error) {
	report := health.Report{
		Time:          time.Now().UTC(),
		ConfigPath:    request.ConfigPath,
		Error:         err.Error(),
		Resolver:      request.Resolver,
		ExpectedExits: request.Exits,
	}
	res := inspection{value: report}
	if !options.json {
		res.text = formatHealthReport(report)
	}
	return res, err
}

func formatHealthReport(r health.Report) string {
	var out strings.Builder
	banner := "PASSED"
	if !r.Passed {
		banner = "FAILED"
	}
	fmt.Fprintf(&out, "Clatch health: %s\n", banner)
	if r.ConfigPath != "" {
		fmt.Fprintf(&out, "Configuration  %s\n", r.ConfigPath)
	}
	if r.Resolver.IsValid() {
		fmt.Fprintf(&out, "Resolver       %s\n", r.Resolver)
	} else {
		fmt.Fprintln(&out, "Resolver       (not configured)")
	}
	if len(r.ExpectedExits) > 0 {
		exits := make([]string, len(r.ExpectedExits))
		for i, ip := range r.ExpectedExits {
			exits[i] = ip.String()
		}
		fmt.Fprintf(&out, "Expected exits %s\n", strings.Join(exits, ", "))
	} else {
		fmt.Fprintln(&out, "Expected exits (not configured)")
	}
	if r.ConntrackError != "" {
		fmt.Fprintf(&out, "Conntrack err  %s\n", r.ConntrackError)
	}
	if len(r.DNS) > 0 {
		out.WriteString("\nDNS probes:\n")
		for _, c := range r.DNS {
			kind := c.TypeName
			if kind == "" {
				kind = fmt.Sprintf("TYPE%d", c.Kind)
			}
			detail := fmt.Sprintf("answers=%d", c.Answers)
			if c.ExpectedEmpty {
				detail += " (expect empty)"
			}
			if c.Error != "" {
				detail = c.Error
			}
			fmt.Fprintf(&out, "  [%-7s] %-18s %-4s %-3s %s\n", strings.ToUpper(c.State), c.Domain, kind, c.Transport, detail)
		}
	}
	if len(r.HTTP) > 0 {
		out.WriteString("\nHTTPS probes:\n")
		for _, c := range r.HTTP {
			target := c.Domain
			if target == "" {
				target = "-"
			}
			var parts []string
			if c.Status != 0 {
				parts = append(parts, fmt.Sprintf("http=%d", c.Status))
			}
			if c.Peer.IsValid() {
				parts = append(parts, "peer="+c.Peer.String())
			}
			if c.Exit.IsValid() {
				parts = append(parts, "exit="+c.Exit.String())
			}
			if len(c.Marks) > 0 {
				parts = append(parts, fmt.Sprintf("marks=%v", c.Marks))
			}
			if c.Error != "" {
				parts = append(parts, c.Error)
			}
			fmt.Fprintf(&out, "  [%-7s] %-8s %-18s %s\n", strings.ToUpper(c.State), c.Role, target, strings.Join(parts, " "))
		}
	}
	if r.Error != "" {
		fmt.Fprintf(&out, "\nError          %s\n", r.Error)
	}
	return out.String()
}
