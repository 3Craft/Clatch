package policy

import (
	"fmt"
	"net/netip"
	"strings"

	"clatch-gateway/internal/guard"
)

// Verdict describes how Clatch treats direct egress traffic to an IP address.
type Verdict struct {
	Address       string   `json:"address"`
	Decision      string   `json:"decision"`
	AllowedDirect bool     `json:"allowed_direct"`
	MatchedPrefix string   `json:"matched_prefix,omitempty"`
	Flags         []string `json:"flags,omitempty"`
	FlagMask      uint32   `json:"flag_mask"`
	Explanation   string   `json:"explanation"`
}

// FlagNames decodes a guard policy flag bitmask into human-readable names.
func FlagNames(mask uint32) []string {
	var names []string
	if mask&guard.Direct != 0 {
		names = append(names, "direct")
	}
	if mask&guard.LAN != 0 {
		names = append(names, "lan")
	}
	if mask&guard.Local != 0 {
		names = append(names, "local")
	}
	if mask&guard.DiagnosticClient != 0 {
		names = append(names, "diagnostic_client")
	}
	if mask&guard.DiagnosticDestination != 0 {
		names = append(names, "diagnostic_destination")
	}
	return names
}

// Explain evaluates longest-prefix match for addr against entries using the
// same precedence as the kernel LPM trie.
func Explain(addr netip.Addr, entries guard.Policy) Verdict {
	addr = addr.Unmap()
	verdict := Verdict{Address: addr.String()}
	if !addr.IsValid() {
		verdict.Decision = "invalid"
		verdict.Explanation = "Invalid IP address."
		return verdict
	}
	if addr.Is6() {
		verdict.Decision = "deny_ipv6"
		verdict.Explanation = "Public IPv6 egress is disabled by Clatch policy; direct IPv6 traffic is dropped."
		return verdict
	}
	var best netip.Prefix
	var bestMask uint32
	matched := false
	for key, flags := range entries {
		prefix, err := key.Prefix()
		if err != nil || !prefix.Addr().Is4() || !prefix.Contains(addr) {
			continue
		}
		if !matched || prefix.Bits() > best.Bits() {
			best = prefix
			bestMask = flags
			matched = true
		}
	}
	if !matched {
		verdict.Decision = "deny_egress"
		verdict.Explanation = fmt.Sprintf(
			"%s does not match any approved direct CIDR; direct egress is blocked by nftables and TCX (traffic must traverse the proxy).",
			addr,
		)
		return verdict
	}
	verdict.MatchedPrefix = best.String()
	verdict.FlagMask = bestMask
	verdict.Flags = FlagNames(bestMask)
	verdict.AllowedDirect = bestMask&guard.Direct != 0

	switch {
	case bestMask&guard.Local != 0:
		verdict.Decision = "allow_local"
		verdict.Explanation = fmt.Sprintf("%s matches gateway local host prefix %s; allowed for local/LAN traffic.", addr, best)
	case bestMask&guard.LAN != 0:
		verdict.Decision = "allow_lan"
		verdict.Explanation = fmt.Sprintf("%s matches protected LAN prefix %s; allowed directly on the LAN.", addr, best)
	case bestMask&guard.Direct != 0:
		verdict.Decision = "allow_direct"
		verdict.Explanation = fmt.Sprintf("%s matches approved direct prefix %s; allowed to egress directly without proxy encapsulation.", addr, best)
	case bestMask&guard.DiagnosticDestination != 0:
		verdict.Decision = "allow_diagnostic"
		verdict.Explanation = fmt.Sprintf("%s matches diagnostic destination %s; blocked for normal egress and allowed only for restricted diagnostic probes.", addr, best)
	default:
		verdict.Decision = "deny_egress"
		verdict.Explanation = fmt.Sprintf("%s matches %s (%s) without the direct flag; direct egress is blocked.", addr, best, strings.Join(verdict.Flags, ", "))
	}
	return verdict
}
