//go:build linux

package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"clatch-gateway/internal/capture"
	"clatch-gateway/internal/gateway"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

type manifest struct {
	Schema    int       `json:"schema"`
	Backup    string    `json:"backup"`
	Unit      string    `json:"unit"`
	Interface string    `json:"interface"`
	Service   string    `json:"service"`
	Created   time.Time `json:"created"`
	Changes   []change  `json:"changes"`
}

type deployment struct {
	Backup string `json:"backup"`
	State  string `json:"state"`
}

func Migrate(action, backup string) (map[string]any, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("migration requires root")
	}
	if action == "plan" {
		return Plan()
	}
	if !filepath.IsAbs(backup) || filepath.Clean(backup) != backup || backup == "/" {
		return nil, fmt.Errorf("migration backup must be a canonical absolute path")
	}
	var result map[string]any
	err := system.WithLock(migrationLock, func() error {
		var err error
		switch action {
		case "apply":
			result, err = apply(backup)
		case "confirm":
			result, err = confirm(backup)
		case "rollback":
			result, err = rollback(backup)
		default:
			err = fmt.Errorf("unknown migration action")
		}
		return err
	})
	return result, err
}

func apply(backup string) (map[string]any, error) {
	p, err := buildPlan()
	if err != nil {
		return nil, err
	}
	artifact, err := runningExecutable()
	if err != nil {
		return nil, err
	}
	before, err := readFile(binaryPath)
	if err != nil {
		return nil, err
	}
	p.Changes = append([]change{{Path: binaryPath, Before: before,
		After: fileState{Exists: true, Mode: 0755, Data: artifact}}}, p.Changes...)
	if err := os.Mkdir(backup, 0700); err != nil {
		return nil, err
	}
	m := manifest{
		Schema: 1, Backup: backup, Unit: "clatch-migration-rollback-" + digest([]byte(backup))[:16],
		Interface: p.Config.Interface, Service: p.Service, Created: time.Now(), Changes: p.Changes,
	}
	if err := writeJSON(filepath.Join(backup, "migration.json"), m); err != nil {
		return nil, err
	}
	if err := system.WriteAtomic(filepath.Join(backup, "clatch-recover"), artifact, 0700); err != nil {
		return nil, err
	}
	statusPath := statePath(p.Config)
	if err := writeJSON(statusPath, deployment{Backup: backup, State: "armed"}); err != nil {
		return nil, err
	}
	if err := m.arm("migrate"); err != nil {
		return nil, fmt.Errorf("activate rollback timer for %s: %w", backup, err)
	}
	status, err := installChanges(p, m)
	if err != nil {
		_, rollbackErr := rollback(backup)
		return nil, errors.Join(fmt.Errorf("migration failed, backup %s: %w", backup, err), rollbackErr)
	}
	if err := writeJSON(statusPath, deployment{Backup: backup, State: "applied"}); err != nil {
		return nil, err
	}
	return map[string]any{"state": "applied", "backup": backup, "rollback_timer": m.Unit + ".timer", "guard": status}, nil
}

func installChanges(p plan, m manifest) (map[string]any, error) {
	for _, item := range m.Changes {
		current, err := readFile(item.Path)
		if err != nil {
			return nil, err
		}
		if !sameFile(current, item.Before) {
			return nil, fmt.Errorf("file changed during planning: %s", item.Path)
		}
		if err := writeFile(item.Path, item.After); err != nil {
			return nil, err
		}
	}
	if _, err := system.Command("", "systemctl", "daemon-reload"); err != nil {
		return nil, err
	}
	if _, err := system.Command("", "systemd-analyze", "verify", guardUnit, p.Service); err != nil {
		return nil, err
	}
	status, err := gateway.Ensure(configPath, p.Config.Interface)
	if err != nil {
		return nil, err
	}
	if status["network_sha256"] != p.PolicySHA {
		return nil, fmt.Errorf("policy changed during migration")
	}
	switch {
	case p.Config.NativeTUN:
		_, err = gateway.NativeHook(configPath, p.Config.NativeConfDir, "post-start")
	case p.Config.IsTUN():
		_, err = capture.StartManagedTUN(configPath)
	default:
		_, err = capture.StartTPROXY(configPath, 0)
	}
	if err != nil {
		return nil, err
	}
	return gateway.Verify(configPath)
}

func confirm(backup string) (map[string]any, error) {
	config, err := policy.ReadConfig(configPath)
	if err != nil {
		return nil, err
	}
	m, current, err := readManifest(config, backup)
	if err != nil {
		return nil, err
	}
	if current.State != "applied" && current.State != "confirmed" {
		return nil, fmt.Errorf("migration has not completed application")
	}
	for _, item := range m.Changes {
		got, err := readFile(item.Path)
		if err != nil {
			return nil, err
		}
		if !sameFile(got, item.After) {
			return nil, fmt.Errorf("installed migration file changed: %s", item.Path)
		}
	}
	for _, unit := range []string{guardUnit, "nftables.service", "networking.service", m.Service} {
		if _, err := system.Command("", "systemctl", "is-active", "--quiet", unit); err != nil {
			return nil, err
		}
	}
	status, err := gateway.Verify(configPath)
	if err != nil {
		return nil, err
	}
	if err := writeJSON(statePath(config), deployment{Backup: backup, State: "confirmed"}); err != nil {
		return nil, err
	}
	if err := m.disarm(); err != nil {
		return nil, err
	}
	return map[string]any{"state": "confirmed", "backup": backup, "guard": status}, nil
}

func rollback(backup string) (map[string]any, error) {
	config, err := policy.ReadConfig(configPath)
	if err != nil {
		return nil, err
	}
	m, _, err := readManifest(config, backup)
	if err != nil {
		return nil, err
	}
	for _, item := range m.Changes {
		current, err := readFile(item.Path)
		if err != nil {
			return nil, err
		}
		if !sameFile(current, item.Before) && !sameFile(current, item.After) {
			return nil, fmt.Errorf("rollback would overwrite an unrelated edit at %s", item.Path)
		}
	}
	for i := len(m.Changes) - 1; i >= 0; i-- {
		item := m.Changes[i]
		if err := writeFile(item.Path, item.Before); err != nil {
			return nil, err
		}
	}
	if _, err := system.Command("", "systemctl", "daemon-reload"); err != nil {
		return nil, err
	}
	if _, err := system.Command("", legacyGuardPath, "--gate-interface", m.Interface, "ensure"); err != nil {
		return nil, fmt.Errorf("legacy startup gate after rollback: %w", err)
	}
	raw, err := system.Command("", legacyGuardPath, "verify")
	if err != nil {
		return nil, err
	}
	var status map[string]any
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, err
	}
	if err := m.disarm(); err != nil {
		return nil, err
	}
	if err := os.Remove(statePath(config)); err != nil {
		return nil, err
	}
	return map[string]any{"state": "rolled_back", "backup": backup, "guard": status}, nil
}

func readManifest(config policy.Config, backup string) (manifest, deployment, error) {
	var current deployment
	data, err := os.ReadFile(statePath(config))
	if err != nil {
		return manifest{}, current, err
	}
	if err := json.Unmarshal(data, &current); err != nil || current.Backup != backup {
		return manifest{}, current, fmt.Errorf("backup does not own the current migration")
	}
	var m manifest
	data, err = os.ReadFile(filepath.Join(backup, "migration.json"))
	if err != nil {
		return m, current, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, current, err
	}
	if m.Schema != 1 || m.Backup != backup || m.Interface != config.Interface ||
		m.Unit != "clatch-migration-rollback-"+digest([]byte(backup))[:16] {
		return m, current, fmt.Errorf("invalid migration manifest")
	}
	return m, current, nil
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return system.WriteAtomic(path, append(data, '\n'), 0600)
}

func writeFile(path string, state fileState) error {
	if state.Exists {
		return system.WriteAtomic(path, state.Data, state.Mode)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (m manifest) arm(action string) error {
	unitDir := "/etc/systemd/system"
	command := strconv.Quote(strings.ReplaceAll(filepath.Join(m.Backup, "clatch-recover"), "%", "%%")) +
		" " + action + " recover " + strconv.Quote(strings.ReplaceAll(m.Backup, "%", "%%"))
	service := "[Unit]\nDescription=Recover an unconfirmed Clatch deployment\n[Service]\nType=oneshot\nExecStart=" + command + "\nTimeoutStartSec=120\n"
	timer := "[Unit]\nDescription=Rollback deadline for unconfirmed Clatch deployment\n[Timer]\nOnActiveSec=10min\nAccuracySec=1s\n[Install]\nWantedBy=timers.target\n"
	for name, text := range map[string]string{m.Unit + ".service": service, m.Unit + ".timer": timer} {
		path := filepath.Join(unitDir, name)
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("migration rollback unit exists or is inaccessible: %s", path)
		}
		if err := system.WriteAtomic(path, []byte(text), 0644); err != nil {
			return err
		}
	}
	if _, err := system.Command("", "systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err := system.Command("", "systemctl", "enable", "--now", m.Unit+".timer")
	return err
}

func (m manifest) disarm() error {
	timer := filepath.Join("/etc/systemd/system", m.Unit+".timer")
	if _, err := os.Lstat(timer); err == nil {
		if _, err := system.Command("", "systemctl", "disable", "--now", m.Unit+".timer"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, suffix := range []string{".timer", ".service"} {
		if err := os.Remove(filepath.Join("/etc/systemd/system", m.Unit+suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_, err := system.Command("", "systemctl", "daemon-reload")
	return err
}

func Recover(backup string) (map[string]any, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("migration recovery requires root")
	}
	var result map[string]any
	err := system.WithLock(migrationLock, func() error {
		config, err := policy.ReadConfig(configPath)
		if err != nil {
			return err
		}
		_, current, err := readManifest(config, backup)
		if err != nil {
			return err
		}
		if current.State == "confirmed" {
			result = map[string]any{"state": "confirmed", "backup": backup}
			return nil
		}
		result, err = rollback(backup)
		return err
	})
	return result, err
}
