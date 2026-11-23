package policy

import (
	"net/netip"
	"testing"
)

func TestExplainLongestPrefixMatch(t *testing.T) {
	cfg := Config{
		Interface:      "ens18",
		DiagnosticUID:  999,
		NativeTUN:      true,
		Pins:           "/sys/fs/bpf/test",
		ApprovedPolicy: "/etc/clatch/approved-policy.json",
		LAN:            []string{"192.0.2.0/24"},
		Local:          []string{"192.0.2.10/32"},
		Diagnostic: &Diagnostic{
			Source:      "192.0.2.20/32",
			Destination: "198.51.100.7/32",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	prefixes, err := Parse([]string{"192.0.2.0/24", "198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	entries := cfg.Entries(Approved{Prefixes: prefixes})

	cases := []struct {
		ip       string
		decision string
		allowed  bool
		prefix   string
	}{
		{"192.0.2.10", "allow_local", true, "192.0.2.10/32"},
		{"192.0.2.50", "allow_lan", true, "192.0.2.0/24"},
		{"198.51.100.42", "allow_direct", true, "198.51.100.0/24"},
		{"198.51.100.7", "allow_direct", true, "198.51.100.7/32"},
		{"1.1.1.1", "deny_egress", false, ""},
		{"2001:db8::1", "deny_ipv6", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			v := Explain(netip.MustParseAddr(tc.ip), entries)
			if v.Decision != tc.decision || v.AllowedDirect != tc.allowed || v.MatchedPrefix != tc.prefix {
				t.Fatalf("Explain(%s) = %+v, want decision=%s allowed=%t prefix=%s",
					tc.ip, v, tc.decision, tc.allowed, tc.prefix)
			}
		})
	}

	// Diagnostic destination outside direct prefixes should only be diagnostic, not direct.
	prefixesOnlyLAN, err := Parse([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	diagOnly := cfg.Entries(Approved{Prefixes: prefixesOnlyLAN})
	v := Explain(netip.MustParseAddr("198.51.100.7"), diagOnly)
	if v.Decision != "allow_diagnostic" || v.AllowedDirect {
		t.Fatalf("expected allow_diagnostic without direct flag, got %+v", v)
	}
}
