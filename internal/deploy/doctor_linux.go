//go:build linux

package deploy

import (
	"fmt"
	"net/netip"
	"os"

	"clatch-gateway/internal/policy"
)

// ProfileCheck describes one non-destructive validation result for an install profile.
type ProfileCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // pass, warn, fail
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

// CheckInstallProfile validates a Debian install profile and checks host
// network/ifupdown alignment without modifying system state.
func CheckInstallProfile(path string) []ProfileCheck {
	var checks []ProfileCheck
	profile, err := readInstallProfile(path)
	if err != nil {
		return []ProfileCheck{{
			ID:      "profile.schema",
			Status:  "fail",
			Message: err.Error(),
			Hint:    "Run `clatch schema install-profile` or `clatch init profile` to compare against the schema.",
		}}
	}
	checks = append(checks, ProfileCheck{
		ID:      "profile.schema",
		Status:  "pass",
		Message: fmt.Sprintf("Valid schema-1 profile for interface %s (%s via %s)", profile.Interface, profile.Address, profile.Gateway),
	})

	if profile.Proxy != nil {
		if _, err := os.Stat(profile.Proxy.Binary); err != nil {
			checks = append(checks, ProfileCheck{
				ID:      "profile.proxy_binary",
				Status:  "fail",
				Message: fmt.Sprintf("Proxy binary not accessible at %s: %v", profile.Proxy.Binary, err),
				Hint:    "Install the proxy binary or update proxy.binary in the profile.",
			})
		} else {
			checks = append(checks, ProfileCheck{
				ID:      "profile.proxy_binary",
				Status:  "pass",
				Message: fmt.Sprintf("Proxy binary found at %s", profile.Proxy.Binary),
			})
		}
		if _, err := os.Stat(profile.Proxy.Config); err != nil {
			checks = append(checks, ProfileCheck{
				ID:      "profile.proxy_config",
				Status:  "fail",
				Message: fmt.Sprintf("Proxy config not accessible at %s: %v", profile.Proxy.Config, err),
				Hint:    "Create the proxy configuration file or update proxy.config in the profile.",
			})
		} else {
			checks = append(checks, ProfileCheck{
				ID:      "profile.proxy_config",
				Status:  "pass",
				Message: fmt.Sprintf("Proxy config found at %s", profile.Proxy.Config),
			})
		}
		if _, err := os.Stat(profile.Proxy.PolicySource); err != nil {
			checks = append(checks, ProfileCheck{
				ID:      "profile.policy_source",
				Status:  "fail",
				Message: fmt.Sprintf("Policy source not accessible at %s: %v", profile.Proxy.PolicySource, err),
				Hint:    "Generate a starter policy with `clatch init policy --output " + profile.Proxy.PolicySource + "`.",
			})
		} else {
			checks = append(checks, ProfileCheck{
				ID:      "profile.policy_source",
				Status:  "pass",
				Message: fmt.Sprintf("Policy source found at %s", profile.Proxy.PolicySource),
			})
		}
	}

	rawIfaces, err := os.ReadFile(interfacesPath)
	if err != nil {
		checks = append(checks, ProfileCheck{
			ID:      "profile.ifupdown",
			Status:  "fail",
			Message: fmt.Sprintf("Cannot read %s: %v", interfacesPath, err),
			Hint:    "Debian installation requires a static IPv4 stanza in /etc/network/interfaces (ifupdown).",
		})
	} else if _, err := gatedInterfaces(string(rawIfaces), profile, binaryPath+" guard ensure "+configPath+" "+profile.Interface); err != nil {
		checks = append(checks, ProfileCheck{
			ID:      "profile.ifupdown",
			Status:  "fail",
			Message: err.Error(),
			Hint:    fmt.Sprintf("Ensure %s defines one static IPv4 stanza for %s matching %s and gateway %s.", interfacesPath, profile.Interface, profile.Address, profile.Gateway),
		})
	} else {
		checks = append(checks, ProfileCheck{
			ID:      "profile.ifupdown",
			Status:  "pass",
			Message: fmt.Sprintf("Static ifupdown stanza in %s matches profile", interfacesPath),
		})
	}

	address := netip.MustParsePrefix(profile.Address)
	cfg := policy.Config{
		Interface: profile.Interface,
		Proxy:     profile.Proxy,
		NativeTUN: profile.NativeMode == "tun",
	}
	if err := verifyInstallNetwork(cfg, address, profile.Gateway); err != nil {
		checks = append(checks, ProfileCheck{
			ID:      "profile.live_network",
			Status:  "warn",
			Message: err.Error(),
			Hint:    "Verify the live interface address, default route, and absence of conflicting TC/XDP filters before running `clatch install apply`.",
		})
	} else {
		checks = append(checks, ProfileCheck{
			ID:      "profile.live_network",
			Status:  "pass",
			Message: fmt.Sprintf("Live interface %s and default route match profile", profile.Interface),
		})
	}
	return checks
}
