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
	recordPath := filepath.Join(filepath.Dir(config.ApprovedPolicy), filepath.Base(installState))
	raw, err := os.ReadFile(recordPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state deployment
	if err := json.Unmarshal(raw, &state); err != nil || state.State == "" ||
		!filepath.IsAbs(state.Backup) || filepath.Clean(state.Backup) != state.Backup || state.Backup == "/" {
		return nil, fmt.Errorf("invalid deployment record at %s", recordPath)
	}
	status := &Status{Kind: "install", State: state.State, Backup: state.Backup}
	if state.State != "armed" && state.State != "applied" {
		return status, nil
	}
	timer := "clatch-install-rollback-" + digest([]byte(state.Backup))[:16] + ".timer"
	status.RollbackDeadline, err = system.TimerDeadline(timer)
	return status, err
}

// PendingBackup resolves the active backup directory recorded for an install
// when the operator omits an explicit backup path.
func PendingBackup() (string, error) {
	raw, err := os.ReadFile(installState)
	if err != nil {
		return "", fmt.Errorf("no active install backup found at %s (pass an explicit backup path): %w", installState, err)
	}
	var state deployment
	if err := json.Unmarshal(raw, &state); err != nil || state.Backup == "" ||
		!filepath.IsAbs(state.Backup) || filepath.Clean(state.Backup) != state.Backup || state.Backup == "/" {
		return "", fmt.Errorf("invalid install deployment record at %s", installState)
	}
	return state.Backup, nil
}
