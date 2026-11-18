//go:build linux

package native

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"clatch-gateway/internal/policy"

	_ "modernc.org/sqlite"
)

const (
	whitelistKey = "system:tproxyWhiteIpGroups"
	settingsKey  = "system:setting"
)

func openDatabase(confdir, mode string) (*sql.DB, error) {
	dsn := url.URL{Scheme: "file", Path: filepath.Join(confdir, "v2raya.db"),
		RawQuery: "mode=" + mode + "&_pragma=busy_timeout(2500)"}
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func readSetting(confdir, key string, value any) error {
	db, err := openDatabase(confdir, "ro")
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = ?", key).Scan(&raw); err != nil {
		return fmt.Errorf("read v2rayA system setting %s: %w", key, err)
	}
	if err := json.Unmarshal(raw, value); err != nil {
		return fmt.Errorf("invalid JSON in v2rayA system setting %s", key)
	}
	return nil
}

// ReplaceWhitelist updates just the approved SQLite key with compare-and-swap.
func ReplaceWhitelist(config policy.Config, before, after json.RawMessage) error {
	if _, err := decodeWhitelist(after); err != nil {
		return err
	}
	db, err := openDatabase(config.NativeConfDir, "rw")
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var current string
	if err := db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = ?", whitelistKey).Scan(&current); err != nil {
		return err
	}
	if !SameWhitelist(json.RawMessage(current), before) {
		return fmt.Errorf("v2rayA whitelist changed concurrently")
	}
	result, err := db.ExecContext(ctx, "UPDATE system_config SET value = ? WHERE key = ? AND value = ?",
		string(after), whitelistKey, current)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("v2rayA whitelist compare-and-swap refused a concurrent update")
	}
	return nil
}

func BackupDatabase(config policy.Config, path string) error {
	// Reserve a private file first; VACUUM INTO accepts an empty target.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	source, err := openDatabase(config.NativeConfDir, "ro")
	if err != nil {
		return err
	}
	defer source.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := source.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return err
	}
	dsn := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	backup, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return err
	}
	defer backup.Close()
	var integrity string
	if err := backup.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return fmt.Errorf("v2rayA database backup failed integrity check")
	}
	return nil
}
