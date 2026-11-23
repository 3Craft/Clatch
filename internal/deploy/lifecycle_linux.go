//go:build linux

package deploy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"clatch-gateway/internal/firewall"
	"clatch-gateway/internal/gateway"
	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

// UpgradeResult reports the outcome of `clatch upgrade`.
type UpgradeResult struct {
	State      string `json:"state"`
	Unchanged  bool   `json:"unchanged,omitempty"`
	BinaryPath string `json:"binary_path"`
	BackupPath string `json:"backup_path,omitempty"`
	OldSHA256  string `json:"old_sha256,omitempty"`
	NewSHA256  string `json:"new_sha256"`
	GuardOK    bool   `json:"guard_verified"`
}

// Upgrade atomically replaces /usr/local/sbin/clatch on an installed gateway
// with the running executable, backing up the previous binary and verifying
// live guard state afterwards.
func Upgrade(configFile, backupDir string) (UpgradeResult, error) {
	if os.Geteuid() != 0 {
		return UpgradeResult{}, fmt.Errorf("upgrade requires root")
	}
	if configFile == "" {
		configFile = configPath
	}
	var res UpgradeResult
	err := system.WithLock(installLock, func() error {
		if _, err := policy.ReadConfig(configFile); err != nil {
			return fmt.Errorf("cannot upgrade without a valid installed config at %s: %w", configFile, err)
		}
		if _, err := gateway.Verify(configFile); err != nil {
			return fmt.Errorf("refusing to upgrade while live guard verification fails: %w", err)
		}
		currentBytes, err := os.ReadFile(binaryPath)
		if err != nil {
			return fmt.Errorf("read installed binary %s: %w", binaryPath, err)
		}
		nextBytes, err := runningExecutable()
		if err != nil {
			return err
		}
		oldSHA := digest(currentBytes)
		newSHA := digest(nextBytes)
		res = UpgradeResult{
			BinaryPath: binaryPath,
			OldSHA256:  oldSHA,
			NewSHA256:  newSHA,
			GuardOK:    true,
		}
		if oldSHA == newSHA {
			res.State = "unchanged"
			res.Unchanged = true
			return nil
		}
		if backupDir == "" {
			backupDir = fmt.Sprintf("/root/clatch-upgrade-%s", time.Now().UTC().Format("20060102T150405Z"))
		}
		if !filepath.IsAbs(backupDir) || filepath.Clean(backupDir) != backupDir || backupDir == "/" {
			return fmt.Errorf("upgrade backup directory must be a canonical absolute path")
		}
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			return err
		}
		backupBin := filepath.Join(backupDir, "clatch.prev")
		if err := system.WriteAtomic(backupBin, currentBytes, 0700); err != nil {
			return err
		}
		res.BackupPath = backupBin
		if err := system.WriteAtomic(binaryPath, nextBytes, 0755); err != nil {
			return err
		}
		if _, err := system.Command("", binaryPath, "guard", "verify", "--config", configFile, "--json"); err != nil {
			restoreErr := system.WriteAtomic(binaryPath, currentBytes, 0755)
			res.GuardOK = false
			res.State = "rolled_back"
			return errors.Join(fmt.Errorf("upgraded binary failed guard verification: %w", err), restoreErr)
		}
		res.State = "upgraded"
		return nil
	})
	return res, err
}

// UninstallOptions configures `clatch uninstall`.
type UninstallOptions struct {
	ConfigPath string
	KeepConfig bool
	Apply      bool
}

// UninstallResult describes planned or completed teardown steps.
type UninstallResult struct {
	Applied    bool     `json:"applied"`
	ConfigPath string   `json:"config"`
	KeepConfig bool     `json:"keep_config"`
	Actions    []string `json:"actions"`
	Warnings   []string `json:"warnings,omitempty"`
}

// Uninstall previews or removes a Clatch gateway installation cleanly.
func Uninstall(opts UninstallOptions) (UninstallResult, error) {
	if os.Geteuid() != 0 {
		return UninstallResult{}, fmt.Errorf("uninstall requires root")
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = configPath
	}
	res := UninstallResult{
		Applied:    opts.Apply,
		ConfigPath: opts.ConfigPath,
		KeepConfig: opts.KeepConfig,
	}

	cfg, cfgErr := policy.ReadConfig(opts.ConfigPath)
	serviceUnit := ""
	if cfgErr == nil {
		if cfg.Proxy != nil {
			serviceUnit = cfg.Proxy.Service
		} else {
			serviceUnit = strings.TrimSuffix(cfg.NativeService, ".service") + ".service"
		}
	}

	var dropIns []string
	dropInUnits := []string{"networking.service", "systemd-networkd.service", "nftables.service"}
	if cfgErr == nil && cfg.Interface != "" {
		netUnit := strings.ReplaceAll(cfg.Interface, "-", `\x2d`)
		dropInUnits = append(dropInUnits, "ifup@"+netUnit+".service")
	}
	if serviceUnit != "" {
		dropInUnits = append(dropInUnits, serviceUnit)
	}
	for _, u := range dropInUnits {
		p := installDropIn(u)
		if _, err := os.Lstat(p); err == nil {
			dropIns = append(dropIns, p)
		}
	}

	var clatchFiles []string
	candidates := []string{
		filepath.Join("/etc/systemd/system", GuardUnit),
		defaultSysctl,
		retainedSysctl,
		hookPath,
		"/usr/local/sbin/gateway-whitelist",
		binaryPath,
	}
	for _, p := range candidates {
		if _, err := os.Lstat(p); err == nil {
			clatchFiles = append(clatchFiles, p)
		}
	}
	for _, wrap := range []string{"/usr/local/bin/ping", "/usr/local/bin/traceroute"} {
		if data, err := os.ReadFile(wrap); err == nil && bytes.Contains(data, []byte(binaryPath+" diagnostic ")) {
			clatchFiles = append(clatchFiles, wrap)
		}
	}

	var configFiles []string
	if !opts.KeepConfig {
		for _, p := range []string{
			opts.ConfigPath,
			defaultPolicy,
			defaultSource,
			defaultRules,
			installState,
			nativePinsRecord,
			policy.DefaultConfigDir + "/clatch-nft.sha256",
		} {
			if _, err := os.Lstat(p); err == nil {
				configFiles = append(configFiles, p)
			}
		}
	}

	hasIfupPreUp := false
	if raw, err := os.ReadFile(interfacesPath); err == nil && strings.Contains(string(raw), "clatch guard ensure") {
		hasIfupPreUp = true
	}

	if cfgErr == nil {
		res.Actions = append(res.Actions,
			fmt.Sprintf("detach pinned TCX egress link on %s (%s)", cfg.Interface, cfg.Pins),
			fmt.Sprintf("delete nftables table inet %s", firewall.TableName),
		)
	}
	if len(dropIns) > 0 {
		res.Actions = append(res.Actions, fmt.Sprintf("remove %d systemd drop-in file(s)", len(dropIns)))
	}
	if hasIfupPreUp {
		res.Actions = append(res.Actions, "remove Clatch pre-up hook from "+interfacesPath)
	}
	for _, f := range clatchFiles {
		res.Actions = append(res.Actions, "remove "+f)
	}
	for _, f := range configFiles {
		res.Actions = append(res.Actions, "remove "+f)
	}
	if len(res.Actions) == 0 {
		res.Warnings = append(res.Warnings, "no Clatch installation artifacts were found")
		return res, nil
	}
	if !opts.Apply {
		return res, nil
	}

	err := system.WithLock(installLock, func() error {
		proxyWasActive := false
		if serviceUnit != "" {
			if active, err := unitActive(serviceUnit); err == nil && active {
				proxyWasActive = true
				_, _ = system.Command("", "systemctl", "stop", serviceUnit)
			}
		}

		// Disable guard service and drop-ins first.
		_, _ = system.Command("", "systemctl", "disable", "--now", GuardUnit)
		for _, p := range dropIns {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				res.Warnings = append(res.Warnings, fmt.Sprintf("remove %s: %v", p, err))
			}
		}

		if hasIfupPreUp {
			if err := stripClatchPreUp(interfacesPath); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("update %s: %v", interfacesPath, err))
			}
		}

		if cfgErr == nil {
			if _, err := os.Lstat(filepath.Join(cfg.Pins, "link")); err == nil {
				if err := guard.Detach(cfg.Interface, cfg.Pins); err != nil {
					res.Warnings = append(res.Warnings, fmt.Sprintf("detach TCX: %v", err))
				}
			}
		}
		for _, tbl := range []string{firewall.TableName, "clatch_tproxy", "clatch_mihomo_tun", "clatch_v2raya_tun", "clatch_v2raya_lan_dns"} {
			_, _ = system.Command("", "nft", "delete", "table", "inet", tbl)
		}

		for _, f := range clatchFiles {
			if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
				res.Warnings = append(res.Warnings, fmt.Sprintf("remove %s: %v", f, err))
			}
		}
		for _, f := range configFiles {
			if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
				res.Warnings = append(res.Warnings, fmt.Sprintf("remove %s: %v", f, err))
			}
		}
		_, _ = system.Command("", "systemctl", "daemon-reload")
		if proxyWasActive && serviceUnit != "" {
			if _, err := system.Command("", "systemctl", "start", serviceUnit); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("restart %s: %v", serviceUnit, err))
			}
		}
		return nil
	})
	return res, err
}

func stripClatchPreUp(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "pre-up ") && strings.Contains(trimmed, "clatch guard ensure") {
			continue
		}
		kept = append(kept, line)
	}
	return system.WriteAtomic(path, []byte(strings.Join(kept, "\n")), info.Mode().Perm())
}
