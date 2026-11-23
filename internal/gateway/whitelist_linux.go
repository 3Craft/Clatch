//go:build linux

package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"clatch-gateway/internal/native"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

const whitelistLock = "/run/lock/gateway-whitelist.lock"

type WhitelistRequest struct {
	Config  string
	Action  string
	Backup  string
	Backups string
	GeoIP   string
	ConfDir string
	Service string
	DNS     string
	Inputs  []string
	Replace bool
	Apply   bool
}

func Whitelist(request WhitelistRequest) (map[string]any, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("native whitelist requires root")
	}
	path, err := filepath.Abs(request.Config)
	if err != nil {
		return nil, err
	}
	request.Config = path
	var result map[string]any
	err = system.WithLock(whitelistLock, func() error {
		config, err := policy.ReadConfig(path)
		if err != nil {
			return err
		}
		if !config.IsNative() {
			return fmt.Errorf("native whitelist requires v2rayA")
		}
		if err := checkWhitelistOptions(config, &request); err != nil {
			return err
		}
		if request.Action == "recover" {
			if !filepath.IsAbs(request.Backup) || filepath.Clean(request.Backup) != request.Backup {
				return fmt.Errorf("invalid recovery backup path")
			}
			result = map[string]any{"recovered": request.Backup}
			return recoverWhitelist(config, request.Config, request.Backup)
		}
		if err := native.CheckMode(config); err != nil {
			return err
		}
		result, err = previewWhitelist(config, request)
		return err
	})
	return result, err
}

func checkWhitelistOptions(config policy.Config, request *WhitelistRequest) error {
	if request.ConfDir != "" && filepath.Clean(request.ConfDir) != config.NativeConfDir {
		return fmt.Errorf("whitelist configuration directory differs from the approved gateway")
	}
	if request.Service != "" && strings.TrimSuffix(request.Service, ".service") != strings.TrimSuffix(config.NativeService, ".service") {
		return fmt.Errorf("whitelist service differs from the approved gateway")
	}
	if request.DNS == "" {
		request.DNS = nativeDNS
		return nil
	}
	endpoint, err := netip.ParseAddrPort(request.DNS)
	if err != nil {
		address, addrErr := netip.ParseAddr(request.DNS)
		if addrErr != nil {
			return fmt.Errorf("whitelist DNS server must be an IPv4 address or address:port")
		}
		endpoint = netip.AddrPortFrom(address, 53)
	}
	if !endpoint.Addr().Is4() || endpoint.Port() == 0 {
		return fmt.Errorf("whitelist DNS server must be an IPv4 address or address:port")
	}
	request.DNS = endpoint.String()
	return nil
}

func previewWhitelist(config policy.Config, request WhitelistRequest) (map[string]any, error) {
	before, err := native.ReadWhitelist(config)
	if err != nil {
		return nil, err
	}
	current, err := native.Approval(config, before, request.GeoIP)
	if err != nil {
		return nil, err
	}
	if request.Action == "restore" {
		raw, err := os.ReadFile(filepath.Join(request.Backup, "whitelist-before.json"))
		if err != nil {
			return nil, err
		}
		request.Inputs, err = native.CustomIPs(raw)
		if err != nil {
			return nil, err
		}
	}
	desired, added, removed, err := native.EditWhitelist(before, request.Action, request.Inputs, request.Replace)
	if err != nil {
		return nil, err
	}
	next, err := native.Approval(config, desired, current.GeoIP)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(desired, &result); err != nil {
		return nil, fmt.Errorf("invalid desired whitelist")
	}
	counts, err := native.GeoIPCounts(next)
	if err != nil {
		return nil, err
	}
	loaded := native.VerifyCapture(config, current) == nil
	result["action"], result["add"], result["remove"], result["applied"] = request.Action, added, removed, false
	result["geoip"], result["geoip_sha256"] = next.GeoIP, next.GeoIPSHA256
	result["group_prefix_counts"] = counts
	result["loaded_nft_matches_installed_data"] = loaded
	approved, err := config.ReadApproved()
	if err != nil {
		return nil, err
	}
	changed := len(added)+len(removed) != 0 || request.Action == "refresh" ||
		!loaded || next.NetworkSHA256 != approved.NetworkSHA256 || next.GeoIPSHA256 != approved.GeoIPSHA256
	result["needs_restart"] = changed
	if request.Apply && request.Action != "show" {
		if changed {
			backup, err := applyWhitelist(config, request, current, next)
			if err != nil {
				return nil, err
			}
			result["applied"], result["backup"] = true, backup
		} else {
			result["unchanged"] = true
		}
	}
	return result, nil
}

func applyWhitelist(config policy.Config, request WhitelistRequest, current, next policy.Approved) (string, error) {
	if err := verifyDNSAt(config.NativeService, request.DNS, []string{"www.baidu.com.", "ip.fm."}); err != nil {
		return "", err
	}
	if !filepath.IsAbs(request.Backups) || filepath.Clean(request.Backups) != request.Backups {
		return "", fmt.Errorf("invalid native backup root")
	}
	if err := os.MkdirAll(request.Backups, 0700); err != nil {
		return "", err
	}
	backup, err := os.MkdirTemp(request.Backups, "clatch-whitelist-")
	if err != nil {
		return "", err
	}
	if err := writeWhitelistBackup(config, backup, current, next); err != nil {
		return "", fmt.Errorf("create whitelist backup %s: %w", backup, err)
	}
	unit, err := armWhitelistRecovery(request.Config, backup)
	if err != nil {
		return "", fmt.Errorf("schedule whitelist recovery for %s: %w", backup, err)
	}

	dir := filepath.Join(backup, "guard")
	err = WithLock(func() error {
		gate, err := open(request.Config)
		if err != nil {
			return err
		}
		if err := native.CheckSavedGeoIP(config, next); err != nil {
			return err
		}
		_, err = stageApproval(gate, dir, next)
		return err
	})
	if err == nil {
		err = restartWithWhitelist(config, current.Whitelist, next.Whitelist)
	}
	if err == nil {
		err = finishNativeUpdate(request.Config, dir, request.DNS)
	}
	if err != nil {
		recovery := recoverWhitelist(config, request.Config, backup)
		if recovery == nil {
			_, recovery = system.Command("", "systemctl", "stop", unit+".timer")
		}
		return "", errors.Join(fmt.Errorf("native whitelist update failed; backup %s: %w", backup, err), recovery)
	}
	_, timerErr := system.Command("", "systemctl", "stop", unit+".timer")
	recordErr := system.WriteAtomic(filepath.Join(backup, "whitelist-after.json"), append(next.Whitelist, '\n'), 0600)
	if err := errors.Join(timerErr, recordErr); err != nil {
		return backup, fmt.Errorf("native whitelist committed with backup %s; follow-up failed: %w", backup, err)
	}
	return backup, nil
}

func writeWhitelistBackup(config policy.Config, backup string, current, next policy.Approved) error {
	if err := native.BackupDatabase(config, filepath.Join(backup, "v2raya.db")); err != nil {
		return err
	}
	for name, data := range map[string][]byte{
		"whitelist-before.json":  current.Whitelist,
		"whitelist-desired.json": next.Whitelist,
	} {
		if err := system.WriteAtomic(filepath.Join(backup, name), data, 0600); err != nil {
			return err
		}
	}
	if err := putJSON(filepath.Join(backup, "geoip-before.json"), map[string]string{
		"path": current.GeoIP, "sha256": current.GeoIPSHA256,
	}); err != nil {
		return err
	}
	rules, err := system.Command("", "nft", "--json", "list", "ruleset")
	if err != nil {
		return err
	}
	if err := system.WriteAtomic(filepath.Join(backup, "nft-before.json"), rules, 0600); err != nil {
		return err
	}
	generated, err := os.ReadFile(filepath.Join(config.NativeConfDir, "config.json"))
	if err != nil {
		return err
	}
	return system.WriteAtomic(filepath.Join(backup, "config.json"), generated, 0600)
}

func armWhitelistRecovery(config, backup string) (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	unit := filepath.Base(backup)
	if _, err := system.Command("", "systemd-run", "--unit="+unit, "--on-active=180s",
		"--timer-property=AccuracySec=1s", executable, "whitelist", "--config", config, "recover", backup); err != nil {
		return "", err
	}
	return unit, nil
}

func restartWithWhitelist(config policy.Config, before, next json.RawMessage) error {
	if _, err := system.Command("", "systemctl", "stop", config.NativeService); err != nil {
		return err
	}
	if err := requireInactive(config.NativeService); err != nil {
		return err
	}
	if !native.SameWhitelist(before, next) {
		if err := native.ReplaceWhitelist(config, before, next); err != nil {
			return err
		}
	}
	_, err := system.Command("", "systemctl", "start", config.NativeService)
	return err
}

func finishNativeUpdate(config, dir, dns string) error {
	deadline := time.Now().Add(50 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		last = WithLock(func() error {
			gate, err := open(config)
			if err != nil {
				return err
			}
			tx, found, err := savedTransaction(gate.Config, config)
			if err != nil {
				return err
			}
			if !found || tx.State != "staged" {
				return fmt.Errorf("native policy stage is missing")
			}
			if dns != nativeDNS {
				if err := verifyDNSAt(gate.Config.NativeService, dns, []string{"www.baidu.com.", "ip.fm."}); err != nil {
					return err
				}
			}
			_, err = finishPolicy(config, dir, "commit")
			return err
		})
		if last == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("native proxy did not become ready before commit: %w", last)
}

func recoverWhitelist(config policy.Config, path, backup string) error {
	dir := filepath.Join(backup, "guard")
	owner, found, err := savedTransaction(config, path)
	if err != nil {
		return err
	}
	if !found {
		// A timer can fire before staging starts or after the transaction ends.
		_, err := os.Stat(filepath.Join(backup, "whitelist-before.json"))
		return err
	}
	raw, err := os.ReadFile(transactionPointer(config))
	if err != nil {
		return err
	}
	var expected string
	if err := json.Unmarshal(raw, &expected); err != nil || expected != dir {
		return fmt.Errorf("backup does not own the pending native policy")
	}
	if owner.State == "committed" || owner.State == "rolled_back" {
		return WithLock(func() error { return recoverPolicy(config, path) })
	}
	before, err := native.ReadWhitelist(config)
	if err != nil {
		return err
	}
	if !native.SameWhitelist(before, owner.Old.Whitelist) && !native.SameWhitelist(before, owner.Desired.Whitelist) {
		return fmt.Errorf("v2rayA whitelist has an unrelated concurrent edit")
	}
	if err := native.CheckSavedGeoIP(config, owner.Old); err != nil {
		return err
	}
	if _, err := system.Command("", "systemctl", "stop", config.NativeService); err != nil {
		return err
	}
	if err := requireInactive(config.NativeService); err != nil {
		return err
	}
	if !native.SameWhitelist(before, owner.Old.Whitelist) {
		if err := native.ReplaceWhitelist(config, before, owner.Old.Whitelist); err != nil {
			return err
		}
	}
	if _, err := PolicyTransaction("rollback", path, dir, "", ""); err != nil {
		return err
	}
	_, err = system.Command("", "systemctl", "start", config.NativeService)
	return err
}
