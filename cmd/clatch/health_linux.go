//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"

	"clatch-gateway/internal/health"
)

func runHealth(args []string) (any, error) {
	var request health.Request
	flags := flag.NewFlagSet("health", flag.ContinueOnError)
	flags.StringVar(&request.DirectURL, "direct-url", "https://www.baidu.com/", "direct application probe")
	flags.StringVar(&request.ProxyURL, "proxy-url", "https://ip.fm/", "application probe that returns the proxy exit address")
	flags.BoolVar(&request.EmptyAAAA, "expect-empty-aaaa", false, "require a successful empty IPv6 DNS answer")
	flags.BoolVar(&request.Marks, "conntrack", false, "check conntrack marks on this gateway")
	flags.Func("dns", "IPv4 resolver address or address:port", func(value string) error {
		address, err := netip.ParseAddrPort(value)
		if err != nil {
			ip, err := netip.ParseAddr(value)
			if err != nil {
				return err
			}
			address = netip.AddrPortFrom(ip, 53)
		}
		if !address.Addr().Is4() || address.Port() == 0 {
			return fmt.Errorf("health requires an IPv4 DNS endpoint")
		}
		request.Resolver = address
		return nil
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
		return nil, err
	}
	if flags.NArg() != 0 || !request.Resolver.IsValid() || len(request.Exits) == 0 {
		return nil, errUsage
	}
	return health.Check(context.Background(), request)
}
