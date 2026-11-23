//go:build linux

package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

const (
	binaryPath  = "/usr/local/sbin/clatch"
	hookPath    = "/usr/local/libexec/clatch-v2raya-hook"
	installLock = "/run/lock/clatch-install.lock"
)

type fileState struct {
	Exists bool        `json:"exists"`
	Mode   os.FileMode `json:"mode"`
	Data   []byte      `json:"data,omitempty"`
}

type change struct {
	Path   string    `json:"path"`
	Before fileState `json:"before"`
	After  fileState `json:"after"`
}

type plan struct {
	Config    policy.Config
	Service   string
	PolicySHA string
	Changes   []change
}

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

func readFile(path string) (fileState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileState{}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fileState{}, fmt.Errorf("deployment requires an ordinary file at %s", path)
	}
	data, err := os.ReadFile(path)
	return fileState{Exists: true, Mode: info.Mode().Perm(), Data: data}, err
}

func sameFile(a, b fileState) bool {
	return a.Exists == b.Exists && a.Mode == b.Mode && bytes.Equal(a.Data, b.Data)
}

func wrapper(command string) []byte {
	return []byte("#!/bin/sh\nexec " + binaryPath + " " + command + " \"$@\"\n")
}

func digest(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
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
			return fmt.Errorf("rollback unit exists or is inaccessible: %s", path)
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
