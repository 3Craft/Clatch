//go:build linux

package deploy

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"clatch-gateway/internal/policy"
)

// CheckInstallProfile validates a Clatch install profile and checks host
// network manager alignment without modifying system state.
func CheckInstallProfile(path string) []ProfileCheck {
	checks := CheckInstallProfileSchema(path)
	if len(checks) == 0 || checks[0].Status != "pass" {
		return checks
	}
	profile, err := ReadInstallProfile(path)
	if err != nil {
		return checks
	}

	var existing []string
	for _, item := range []string{configPath, binaryPath, defaultPolicy, defaultRules,
		defaultSource, defaultPins, defaultSysctl, filepath.Join("/etc/systemd/system", GuardUnit),
		installState, retainedSysctl, nativePinsRecord} {
		if _, err := os.Lstat(item); !errors.Is(err, os.ErrNotExist) {
			existing = append(existing, item)
		}
	}
	if len(existing) == 0 {
		checks = append(checks, ProfileCheck{
			ID:      "profile.clean_host",
			Status:  "pass",
			Message: "No conflicting Clatch installation artifacts found",
		})
	} else {
		checks = append(checks, ProfileCheck{
			ID:      "profile.clean_host",
			Status:  "fail",
			Message: fmt.Sprintf("Existing Clatch artifact(s) found: %s", existing[0]),
			Hint:    "Run `clatch upgrade` to update an installed gateway or `clatch uninstall --yes` to clean leftover artifacts.",
		})
	}

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

	if stack, err := detectNetworkStack(profile); err != nil {
		checks = append(checks, ProfileCheck{
			ID:      "profile.network_stack",
			Status:  "fail",
			Message: err.Error(),
			Hint:    fmt.Sprintf("Ensure %s defines one static IPv4 stanza for %s matching %s and gateway %s, or use systemd-networkd.", interfacesPath, profile.Interface, profile.Address, profile.Gateway),
		})
	} else {
		checks = append(checks, ProfileCheck{
			ID:      "profile.network_stack",
			Status:  "pass",
			Message: fmt.Sprintf("Detected supported network manager: %s", stack),
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
