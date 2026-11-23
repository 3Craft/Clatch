//go:build linux

package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

type Status struct {
	Kind             string     `json:"kind"`
	State            string     `json:"state"`
	Backup           string     `json:"backup"`
	RollbackDeadline *time.Time `json:"rollback_deadline,omitempty"`
}

func LocalStatus(config policy.Config) (*Status, error) {
	for _, record := range []struct{ kind, path string }{
		{"migration", statePath(config)},
		{"install", filepath.Join(filepath.Dir(config.ApprovedPolicy), filepath.Base(installState))},
	} {
		raw, err := os.ReadFile(record.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var state deployment
		if err := json.Unmarshal(raw, &state); err != nil || state.State == "" ||
			!filepath.IsAbs(state.Backup) || filepath.Clean(state.Backup) != state.Backup || state.Backup == "/" {
			return nil, fmt.Errorf("invalid deployment record at %s", record.path)
		}
		status := &Status{Kind: record.kind, State: state.State, Backup: state.Backup}
		if state.State != "armed" && state.State != "applied" {
			return status, nil
		}
		timer := "clatch-" + record.kind + "-rollback-" + digest([]byte(state.Backup))[:16] + ".timer"
		status.RollbackDeadline, err = system.TimerDeadline(timer)
		return status, err
	}
	return nil, nil
}

// PendingBackup resolves the active backup directory recorded for an install
// or migration when the operator omits an explicit backup path.
func PendingBackup(kind string) (string, error) {
	var recordPath string
	switch kind {
	case "install":
		recordPath = installState
	case "migrate":
		config, err := policy.ReadConfig(legacyConfigPath)
		if err != nil {
			return "", fmt.Errorf("read legacy config to locate migration backup: %w", err)
		}
		recordPath = statePath(config)
	default:
		return "", fmt.Errorf("unknown deployment kind %q", kind)
	}
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		return "", fmt.Errorf("no active %s backup found at %s (pass an explicit backup path): %w", kind, recordPath, err)
	}
	var state deployment
	if err := json.Unmarshal(raw, &state); err != nil || state.Backup == "" ||
		!filepath.IsAbs(state.Backup) || filepath.Clean(state.Backup) != state.Backup || state.Backup == "/" {
		return "", fmt.Errorf("invalid %s deployment record at %s", kind, recordPath)
	}
	return state.Backup, nil
}
