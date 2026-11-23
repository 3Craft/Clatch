package deploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"

	"clatch-gateway/internal/policy"
)

// InstallProfile describes the declarative input to `clatch install plan|apply`.
type InstallProfile struct {
	Schema      int                `json:"schema"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Interface   string             `json:"interface"`
	Address     string             `json:"address"`
	Gateway     string             `json:"gateway"`
	LAN         []string           `json:"lan"`
	PublicIPv6  bool               `json:"public_ipv6"`
	Proxy       *policy.Proxy      `json:"proxy"`
	NativeMode  string             `json:"native_mode"`
	GeoIP       string             `json:"geoip"`
	Diagnostic  *policy.Diagnostic `json:"lan_icmp_diagnostic"`
}

// ProfileCheck describes one non-destructive validation result for an install profile.
type ProfileCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // pass, warn, fail
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

var installInterface = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,14}$`)

// ReadInstallProfile parses and strictly validates a Clatch install profile JSON.
func ReadInstallProfile(path string) (InstallProfile, error) {
	var profile InstallProfile
	raw, err := os.ReadFile(path)
	if err != nil {
		return profile, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return profile, err
	}
	if decoder.Decode(new(any)) != io.EOF || profile.Schema != 1 || profile.PublicIPv6 ||
		!installInterface.MatchString(profile.Interface) || profile.Interface == "lo" {
		return profile, fmt.Errorf("expected a schema-1 single-interface IPv4 profile")
	}
	address, err := netip.ParsePrefix(profile.Address)
	upstream, gatewayErr := netip.ParseAddr(profile.Gateway)
	if err != nil || gatewayErr != nil || !address.Addr().Is4() || !upstream.Is4() ||
		!address.Addr().IsGlobalUnicast() || !upstream.IsGlobalUnicast() ||
		address.Bits() == 0 || address.Addr() == upstream || !address.Contains(upstream) ||
		!usableSubnetHost(address.Masked(), address.Addr()) || !usableSubnetHost(address.Masked(), upstream) {
		return profile, fmt.Errorf("static address and upstream must be distinct IPv4 hosts on the connected subnet")
	}
	if len(profile.LAN) == 0 {
		return profile, fmt.Errorf("LAN requires at least one canonical IPv4 prefix")
	}
	for _, entry := range profile.LAN {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 || prefix.Masked() != prefix {
			return profile, fmt.Errorf("LAN requires explicit canonical IPv4 prefixes")
		}
	}
	if profile.Proxy != nil {
		if profile.NativeMode != "" {
			return profile, fmt.Errorf("native_mode is only available for a v2rayA profile")
		}
		if profile.GeoIP != "" {
			return profile, fmt.Errorf("standalone profiles use a CIDR policy file, not geoip")
		}
		cfg := policy.Config{
			Interface:      profile.Interface,
			DiagnosticUID:  999,
			Pins:           "/sys/fs/bpf/clatch",
			ApprovedPolicy: policy.DefaultConfigDir + "/approved-policy.json",
			LAN:            profile.LAN,
			Local:          []string{address.Addr().String() + "/32"},
			Proxy:          profile.Proxy,
			Diagnostic:     profile.Diagnostic,
		}
		if err := cfg.Validate(); err != nil {
			return profile, err
		}
	} else if profile.NativeMode != "" && profile.NativeMode != "tproxy" && profile.NativeMode != "tun" {
		return profile, fmt.Errorf("native_mode must be tproxy or tun")
	}
	return profile, nil
}

func usableSubnetHost(prefix netip.Prefix, address netip.Addr) bool {
	if prefix.Bits() >= 31 {
		return true
	}
	return prefix.Contains(address) && address != prefix.Addr() && prefix.Contains(address.Next())
}

// CheckInstallProfileSchema validates only the declarative schema of an install
// profile file, suitable for offline/non-Linux checks (such as macOS).
func CheckInstallProfileSchema(path string) []ProfileCheck {
	profile, err := ReadInstallProfile(path)
	if err != nil {
		return []ProfileCheck{{
			ID:      "profile.schema",
			Status:  "fail",
			Message: err.Error(),
			Hint:    "Run `clatch schema install-profile` or `clatch init profile` to compare against the schema.",
		}}
	}
	return []ProfileCheck{{
		ID:      "profile.schema",
		Status:  "pass",
		Message: fmt.Sprintf("Valid schema-1 profile for interface %s (%s via %s)", profile.Interface, profile.Address, profile.Gateway),
	}}
}
