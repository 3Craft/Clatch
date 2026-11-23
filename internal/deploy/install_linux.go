//go:build linux

package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"clatch-gateway/internal/firewall"
	"clatch-gateway/internal/gateway"
	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

const (
	retainedSysctl   = "/etc/sysctl.d/99-zzzz-clatch-retained.conf"
	nativePinsRecord = policy.DefaultConfigDir + "/native-tun-generations.json"
)

type installManifest struct {
	manifest
	Config        policy.Config   `json:"config"`
	Approval      policy.Approved `json:"approval"`
	ProfileSHA    string          `json:"profile_sha256"`
	ProxyActive   bool            `json:"proxy_active"`
	NFTActive     bool            `json:"nft_active"`
	NFTEnabled    string          `json:"nft_enabled"`
	NetworkActive bool            `json:"network_active"`
	NetworkStack  string          `json:"network_stack,omitempty"`
	Sysctls       []string        `json:"sysctls"`
}

func Install(action, profile, backup string) (map[string]any, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("installation requires root")
	}
	if action == "plan" {
		if result, found, err := existingInstall(profile); found || err != nil {
			return result, err
		}
		p, err := makeInstallPlan(profile, false)
		if err != nil {
			return nil, err
		}
		paths := []string{binaryPath, defaultPolicy, defaultRules, installState}
		for _, change := range p.Changes {
			paths = append(paths, change.Path)
		}
		return map[string]any{
			"interface": p.Config.Interface, "backend": p.Service, "network_sha256": p.PolicySHA,
			"network_stack": p.NetworkStack, "files": paths, "backend_active": p.ProxyActive,
			"diagnostic_uid": p.Config.DiagnosticUID,
		}, nil
	}
	if !filepath.IsAbs(backup) || filepath.Clean(backup) != backup || backup == "/" {
		return nil, fmt.Errorf("install backup must be a canonical absolute path")
	}
	var result map[string]any
	err := system.WithLock(installLock, func() error {
		var err error
		switch action {
		case "apply":
			result, err = applyInstall(profile, backup)
		case "confirm":
			result, err = confirmInstall(backup)
		case "rollback", "recover":
			result, err = rollbackInstall(backup, action == "recover")
		default:
			err = fmt.Errorf("unknown install action")
		}
		return err
	})
	return result, err
}

func readInstallState() (deployment, error) {
	var current deployment
	raw, err := os.ReadFile(installState)
	if err != nil {
		return current, err
	}
	if err := json.Unmarshal(raw, &current); err != nil || !filepath.IsAbs(current.Backup) || filepath.Clean(current.Backup) != current.Backup {
		return current, fmt.Errorf("invalid installation ownership record")
	}
	return current, nil
}

func readInstallManifest(backup string) (installManifest, deployment, error) {
	var m installManifest
	current, err := readInstallState()
	if err != nil {
		return m, current, err
	}
	if current.Backup != backup {
		return m, current, fmt.Errorf("backup does not own the installed gateway")
	}
	raw, err := os.ReadFile(filepath.Join(backup, "install.json"))
	if err != nil {
		return m, current, err
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.Schema != 1 || m.Backup != backup || m.Interface != m.Config.Interface ||
		m.Unit != "clatch-install-rollback-"+digest([]byte(backup))[:16] || m.Config.Pins != defaultPins || m.Config.ApprovedPolicy != defaultPolicy {
		return m, current, fmt.Errorf("invalid installation backup manifest")
	}
	if err := m.Config.Validate(); err != nil {
		return m, current, err
	}
	m.Approval, err = m.Config.ValidateApproved(m.Approval)
	return m, current, err
}

func existingInstall(profile string) (map[string]any, bool, error) {
	current, err := readInstallState()
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	m, _, err := readInstallManifest(current.Backup)
	if err != nil {
		return nil, true, err
	}
	if current.State != "applied" && current.State != "confirmed" {
		return nil, true, fmt.Errorf("installation is %s; use its existing backup", current.State)
	}
	raw, err := os.ReadFile(profile)
	if err != nil {
		return nil, true, err
	}
	if digest(raw) != m.ProfileSHA {
		return nil, true, fmt.Errorf("profile differs from the installed gateway")
	}
	artifact, err := runningExecutable()
	if err != nil {
		return nil, true, err
	}
	if len(m.Changes) == 0 || m.Changes[0].Path != binaryPath || digest(artifact) != digest(m.Changes[0].After.Data) {
		return nil, true, fmt.Errorf("executable differs from the installed gateway (use `clatch upgrade` to update the binary)")
	}
	status, err := verifyInstall(m)
	return map[string]any{"unchanged": true, "state": current.State, "backup": m.Backup, "guard": status}, true, err
}

func runningExecutable() ([]byte, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(executable)
}

func applyInstall(profile, backup string) (map[string]any, error) {
	if result, found, err := existingInstall(profile); found || err != nil {
		return result, err
	}
	profileRaw, err := os.ReadFile(profile)
	if err != nil {
		return nil, err
	}
	p, err := makeInstallPlan(profile, true)
	if err != nil {
		return nil, err
	}
	if current, err := os.ReadFile(profile); err != nil || digest(current) != digest(profileRaw) {
		return nil, fmt.Errorf("profile changed during installation preflight")
	}
	artifact, err := runningExecutable()
	if err != nil {
		return nil, err
	}
	m := installManifest{
		manifest: manifest{Schema: 1, Backup: backup, Unit: "clatch-install-rollback-" + digest([]byte(backup))[:16],
			Interface: p.Config.Interface, Service: p.Service, Created: time.Now().UTC()},
		Config: p.Config, Approval: p.Approval, ProfileSHA: digest(profileRaw),
		ProxyActive: p.ProxyActive, NFTActive: p.NFTActive, NFTEnabled: p.NFTEnabled,
		NetworkStack: p.NetworkStack,
	}
	netUnit := "networking.service"
	if p.NetworkStack == "systemd-networkd" {
		netUnit = "systemd-networkd.service"
	}
	m.NetworkActive, err = unitActive(netUnit)
	if err != nil {
		return nil, err
	}
	m.Changes = append([]change{{Path: binaryPath, After: fileState{Exists: true, Mode: 0755, Data: artifact}}}, p.Changes...)
	for _, key := range p.sysctlKeys() {
		raw, err := system.Command("", "sysctl", "-n", key)
		if err != nil {
			return nil, err
		}
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			return nil, fmt.Errorf("invalid runtime sysctl value for %s", key)
		}
		m.Sysctls = append(m.Sysctls, key+"="+string(raw[:len(raw)-1]))
	}
	if err := os.Mkdir(backup, 0700); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(backup, "install.json"), m); err != nil {
		return nil, err
	}
	if err := system.WriteAtomic(filepath.Join(backup, "clatch-recover"), artifact, 0700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(installState), 0700); err != nil {
		return nil, err
	}
	if err := writeJSON(installState, deployment{Backup: backup, State: "armed"}); err != nil {
		return nil, err
	}
	if err := m.arm("install"); err != nil {
		return nil, fmt.Errorf("arm rollback for %s: %w", backup, err)
	}
	status, err := m.apply(p.NewAccount)
	if err != nil {
		_, recovery := rollbackInstall(backup, false)
		return nil, errors.Join(fmt.Errorf("install with backup %s: %w", backup, err), recovery)
	}
	if err := writeJSON(installState, deployment{Backup: backup, State: "applied"}); err != nil {
		return nil, err
	}
	return map[string]any{
		"state": "applied", "backup": backup, "network_stack": m.NetworkStack,
		"rollback_timer": m.Unit + ".timer", "backend_active": m.ProxyActive, "guard": status,
	}, nil
}

func (m installManifest) apply(createAccount bool) (map[string]any, error) {
	if err := stopForwarding(); err != nil {
		return nil, err
	}
	if m.ProxyActive {
		if _, err := system.Command("", "systemctl", "stop", m.Service); err != nil {
			return nil, err
		}
	}
	if createAccount {
		if _, err := system.Command("", "useradd", "--system", "--uid", strconv.FormatUint(uint64(m.Config.DiagnosticUID), 10),
			"--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", traceAccount); err != nil {
			return nil, err
		}
	}
	if err := m.checkInstallFiles(false); err != nil {
		return nil, err
	}
	for _, item := range m.Changes {
		if err := os.MkdirAll(filepath.Dir(item.Path), 0755); err != nil {
			return nil, err
		}
		if err := writeFile(item.Path, item.After); err != nil {
			return nil, err
		}
	}
	if _, err := os.Lstat(defaultPolicy); !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("approved policy file appeared during installation")
	}
	if err := writeJSON(defaultPolicy, m.Approval); err != nil {
		return nil, err
	}
	if _, err := gateway.Ensure(configPath, m.Interface); err != nil {
		return nil, err
	}
	if _, err := system.Command("", "systemctl", "daemon-reload"); err != nil {
		return nil, err
	}
	verifyUnits := []string{GuardUnit}
	if m.NFTEnabled != "" {
		verifyUnits = append(verifyUnits, "nftables.service")
	}
	if _, err := system.Command("", "systemd-analyze", append([]string{"verify", "--man=no"}, verifyUnits...)...); err != nil {
		return nil, err
	}
	if _, err := system.Command("", "systemctl", append([]string{"enable", "--now"}, verifyUnits...)...); err != nil {
		return nil, err
	}
	if m.ProxyActive {
		if _, err := system.Command("", "systemctl", "start", m.Service); err != nil {
			return nil, err
		}
	}
	return verifyInstall(m)
}

func (m installManifest) checkInstallFiles(rollback bool) error {
	for _, item := range m.Changes {
		current, err := readFile(item.Path)
		if err != nil {
			return err
		}
		if !sameFile(current, item.Before) && !(rollback && m.matchesInstalled(item, current)) {
			return fmt.Errorf("unrelated local edit at %s", item.Path)
		}
	}
	return nil
}

func (m installManifest) matchesInstalled(item change, current fileState) bool {
	if sameFile(current, item.After) {
		return true
	}
	if !m.Config.NativeTUN || item.Path != configPath || !current.Exists || current.Mode != item.After.Mode {
		return false
	}
	var expected, actual map[string]json.RawMessage
	if json.Unmarshal(item.After.Data, &expected) != nil || json.Unmarshal(current.Data, &actual) != nil {
		return false
	}
	var pins string
	if json.Unmarshal(actual["pins"], &pins) != nil {
		return false
	}
	known, err := nativePinPaths()
	if err != nil || !slices.Contains(known, pins) {
		return false
	}
	actual["pins"] = expected["pins"]
	return reflect.DeepEqual(actual, expected)
}

func nativePinPaths() ([]string, error) {
	var record struct {
		Schema      int      `json:"schema"`
		Original    string   `json:"original"`
		Generations []string `json:"generations"`
	}
	raw, err := os.ReadFile(nativePinsRecord)
	if errors.Is(err, os.ErrNotExist) {
		return []string{defaultPins}, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &record) != nil || record.Schema != 1 || record.Original != defaultPins {
		return nil, fmt.Errorf("invalid native TUN generation ownership record")
	}
	pins := []string{record.Original}
	for _, path := range record.Generations {
		if path == defaultPins {
			continue
		}
		timestamp, ok := strings.CutPrefix(path, "/sys/fs/bpf/clatch-v2raya-tun-")
		if _, err := strconv.ParseUint(timestamp, 10, 64); !ok || err != nil {
			return nil, fmt.Errorf("invalid native TUN generation pin path")
		}
		pins = append(pins, path)
	}
	return pins, nil
}

func verifyInstall(m installManifest) (map[string]any, error) {
	for _, item := range m.Changes {
		current, err := readFile(item.Path)
		if err != nil {
			return nil, err
		}
		if !m.matchesInstalled(item, current) {
			return nil, fmt.Errorf("installed file differs at %s", item.Path)
		}
	}
	status, err := gateway.Verify(configPath)
	if err != nil {
		return nil, err
	}
	if status["network_sha256"] != m.Approval.NetworkSHA256 {
		return nil, fmt.Errorf("approved policy differs from the installation snapshot")
	}
	return status, nil
}

func confirmInstall(backup string) (map[string]any, error) {
	m, current, err := readInstallManifest(backup)
	if err != nil {
		return nil, err
	}
	if current.State != "applied" && current.State != "confirmed" {
		return nil, fmt.Errorf("fresh installation is not ready for confirmation")
	}
	status, err := verifyInstall(m)
	if err != nil {
		return nil, err
	}
	if err := gateway.CheckBackendDNS(m.Config); err != nil {
		return nil, err
	}
	if err := writeJSON(installState, deployment{Backup: backup, State: "confirmed"}); err != nil {
		return nil, err
	}
	if err := m.disarm(); err != nil {
		return nil, err
	}
	return map[string]any{"state": "confirmed", "backup": backup, "guard": status}, nil
}

func stopForwarding() error {
	_, err := system.Command("", "sysctl", "-q", "-w", "net.ipv4.ip_forward=0", "net.ipv6.conf.all.forwarding=0", "net.ipv6.conf.default.forwarding=0")
	return err
}

func rollbackInstall(backup string, automatic bool) (map[string]any, error) {
	m, state, err := readInstallManifest(backup)
	if err != nil {
		return nil, err
	}
	if automatic && state.State == "confirmed" {
		return map[string]any{"state": "confirmed"}, nil
	}
	if err := m.checkInstallFiles(true); err != nil {
		return nil, err
	}
	if current, err := m.Config.ReadApproved(); err == nil {
		if current.NetworkSHA256 != m.Approval.NetworkSHA256 {
			return nil, fmt.Errorf("approved policy differs from the original installation")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := m.restore(); err != nil {
		return nil, err
	}
	if err := m.disarm(); err != nil {
		return nil, err
	}
	if err := os.Remove(installState); err != nil {
		return nil, err
	}
	return map[string]any{"state": "rolled_back", "backup": backup, "protection_retained": !m.ProxyActive}, nil
}

func (m installManifest) restore() error {
	if err := stopForwarding(); err != nil {
		return err
	}
	if _, err := system.Command("", "systemctl", "stop", m.Service); err != nil {
		return err
	}
	if m.Config.NativeTUN {
		pins, err := nativePinPaths()
		if err != nil {
			return err
		}
		for _, path := range pins {
			if _, err := guard.Verify(m.Interface, path); err == nil {
				m.Config.Pins = path
				break
			}
		}
	}
	if err := m.emergencyGuard(); err != nil {
		return err
	}
	if m.NFTEnabled != "" && !m.NFTActive {
		if _, err := system.Command("", "systemctl", "stop", "nftables.service"); err != nil {
			return err
		}
	}
	for i := len(m.Changes) - 1; i >= 0; i-- {
		item := m.Changes[i]
		if err := writeFile(item.Path, item.Before); err != nil {
			return err
		}
	}
	if _, err := system.Command("", "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := m.restoreUnits(); err != nil {
		return err
	}
	if err := m.emergencyGuard(); err != nil {
		return err
	}
	return m.restoreConnectivity()
}

func (m installManifest) restoreUnits() error {
	link := filepath.Join("/etc/systemd/system/sysinit.target.wants", GuardUnit)
	if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if m.NFTEnabled != "" && m.NFTEnabled != "enabled" {
		if _, err := system.Command("", "systemctl", "disable", "nftables.service"); err != nil {
			return err
		}
		if m.NFTEnabled == "enabled-runtime" {
			if _, err := system.Command("", "systemctl", "enable", "--runtime", "nftables.service"); err != nil {
				return err
			}
		}
	}
	if m.NFTActive {
		if _, err := system.Command("", "systemctl", "start", "nftables.service"); err != nil {
			return err
		}
	}
	if m.NetworkActive {
		netUnit := "networking.service"
		if m.NetworkStack == "systemd-networkd" {
			netUnit = "systemd-networkd.service"
		}
		_, err := system.Command("", "systemctl", "start", netUnit)
		return err
	}
	return nil
}

func (m installManifest) emergencyGuard() error {
	if err := system.MountBPF(); err != nil {
		return err
	}
	settings := guard.Settings{DiagnosticUID: m.Config.DiagnosticUID}
	if _, err := os.Lstat(filepath.Join(m.Config.Pins, "link")); errors.Is(err, os.ErrNotExist) {
		if _, err := guard.Attach(m.Interface, "-", m.Config.Pins, m.Config.Entries(m.Approval), settings); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if _, err := guard.Verify(m.Interface, m.Config.Pins); err != nil {
		return err
	}
	if _, err := guard.CheckPolicy(m.Config.Pins, m.Config.Entries(m.Approval), settings); err != nil {
		return err
	}
	rules, err := firewall.RenderGuard(m.Config, m.Approval, 0)
	if err != nil {
		return err
	}
	_, err = system.Command(rules, "nft", "-f", "-")
	return err
}

func (m installManifest) restoreConnectivity() error {
	iface, err := net.InterfaceByName(m.Interface)
	if err != nil {
		return err
	}
	if iface.Flags&net.FlagUp == 0 {
		if m.NetworkStack == "systemd-networkd" {
			if _, err := system.Command("", "ip", "link", "set", "dev", m.Interface, "up"); err != nil {
				return err
			}
		} else {
			if _, err := system.Command("", "ifup", "--force", m.Interface); err != nil {
				return err
			}
		}
	}
	if m.ProxyActive {
		if _, err := system.Command("", "systemctl", "start", m.Service); err != nil {
			return err
		}
		if err := waitBackendDNS(m.Config); err != nil {
			return err
		}
		if m.Config.NativeTUN {
			if err := m.pruneNativePins(); err != nil {
				return err
			}
		}
		if err := guard.Detach(m.Interface, m.Config.Pins); err != nil {
			return err
		}
		if m.Config.NativeTUN {
			if err := os.Remove(nativePinsRecord); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if _, err := system.Command("", "nft", "delete", "table", "inet", firewall.TableName); err != nil {
			return err
		}
		if _, err := system.Command("", "sysctl", append([]string{"-q", "-w"}, m.Sysctls...)...); err != nil {
			return err
		}
	} else {
		const disabled = "net.ipv4.ip_forward=0\nnet.ipv6.conf.all.forwarding=0\nnet.ipv6.conf.default.forwarding=0\n"
		if err := system.WriteAtomic(retainedSysctl, []byte(disabled), 0644); err != nil {
			return err
		}
		if err := stopForwarding(); err != nil {
			return err
		}
	}
	for _, path := range []string{defaultPolicy, defaultRules, policy.DefaultConfigDir + "/clatch-nft.sha256"} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (m installManifest) pruneNativePins() error {
	pins, err := nativePinPaths()
	if err != nil {
		return err
	}
	for _, path := range pins {
		if path == m.Config.Pins {
			continue
		}
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if _, err := guard.Prune(m.Interface, m.Config.Pins, path); err != nil {
			return err
		}
	}
	return nil
}

func waitBackendDNS(config policy.Config) error {
	deadline := time.Now().Add(40 * time.Second)
	for {
		err := gateway.CheckBackendDNS(config)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}
