//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
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
		return failedHealth(request, err)
	}
	specified := make(map[string]bool)
	flags.Visit(func(flag *flag.Flag) { specified[flag.Name] = true })
	if !specified["conntrack"] {
		request.Marks = defaults.Conntrack
	}
	if !specified["expect-empty-aaaa"] {
		request.EmptyAAAA = defaults.EmptyAAAA
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
			return failedHealth(request, err)
		}
		if err == nil && !request.Resolver.IsValid() {
			request.Resolver = health.LocalResolver(config)
		}
	}
	report, err := health.Check(context.Background(), request)
	return inspection{value: report}, err
}

func failedHealth(request health.Request, err error) (inspection, error) {
	return inspection{value: health.Report{Time: time.Now().UTC(), ConfigPath: request.ConfigPath,
		Error: err.Error(), Resolver: request.Resolver, ExpectedExits: request.Exits}}, err
}
