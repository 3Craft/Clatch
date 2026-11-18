//go:build linux

package native

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

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
