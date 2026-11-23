//go:build linux

package health

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestReadDefaultsCustomProbes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	healthPath := filepath.Join(dir, "health.json")
	raw := `{
		"dns": "192.0.2.1:5353",
		"expected_exits": ["203.0.113.10"],
		"conntrack": true,
		"expect_empty_aaaa": true,
		"direct_url": "https://example.org/",
		"proxy_url": "https://ifconfig.me/ip",
		"dns_probes": [
			{"domain": "example.org", "type": "a"},
			{"domain": "example.com", "type": "AAAA"}
		]
	}`
	if err := os.WriteFile(healthPath, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	defaults, err := ReadDefaults(cfgPath)
	if err != nil {
		t.Fatalf("ReadDefaults failed: %v", err)
	}
	if defaults.DirectURL != "https://example.org/" || defaults.ProxyURL != "https://ifconfig.me/ip" {
		t.Fatalf("unexpected custom URLs: %+v", defaults)
	}
	if len(defaults.DNSProbes) != 2 || defaults.DNSProbes[0].Type != "A" || defaults.DNSProbes[1].Type != "AAAA" {
		t.Fatalf("unexpected DNSProbes: %+v", defaults.DNSProbes)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	report, err := Check(ctx, Request{
		Resolver:  netip.MustParseAddrPort("127.0.0.1:53"),
		DirectURL: defaults.DirectURL,
		ProxyURL:  defaults.ProxyURL,
		Exits:     defaults.ExpectedExits,
		DNSProbes: defaults.DNSProbes,
	})
	if err == nil || len(report.DNS) != 4 {
		t.Fatalf("expected 4 DNS checks (2 probes x udp/tcp), got %d (err=%v)", len(report.DNS), err)
	}
	if report.DNS[0].TypeName != "A" || report.DNS[2].TypeName != "AAAA" {
		t.Fatalf("missing human-readable type_name in DNS checks: %+v", report.DNS)
	}
}

func TestReadDefaultsRejectsInvalidCustomProbes(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"bad_url_scheme", `{"direct_url": "ftp://example.org/"}`},
		{"bad_dns_type", `{"dns_probes": [{"domain": "example.org", "type": "MX"}]}`},
		{"empty_dns_domain", `{"dns_probes": [{"domain": "", "type": "A"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "health.json"), []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadDefaults(filepath.Join(dir, "config.json")); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}
