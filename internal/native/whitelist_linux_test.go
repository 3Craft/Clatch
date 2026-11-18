//go:build linux

package native

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"clatch-gateway/internal/policy"
)

func TestWhitelistCASAndBackup(t *testing.T) {
	conf := policy.Config{NativeConfDir: t.TempDir()}
	db, err := sql.Open("sqlite", filepath.Join(conf.NativeConfDir, "v2raya.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := json.RawMessage(`{"countryCodes":["CN","PRIVATE"],"customIps":["198.18.0.1/32","198.18.0.2/32"],"other":{"id":9007199254740993}}`)
	if _, err := db.Exec("CREATE TABLE system_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO system_config VALUES (?, ?), (?, ?)", whitelistKey, string(old), "other-key", "keep"); err != nil {
		t.Fatal(err)
	}
	next, _, removed, err := EditWhitelist(old, "remove", []string{"198.18.0.1"}, false)
	if err != nil || !slices.Equal(removed, []string{"198.18.0.1/32"}) {
		t.Fatalf("exact removal: %v: %v", removed, err)
	}
	backup := filepath.Join(t.TempDir(), "v2raya.db")
	if err := BackupDatabase(conf, backup); err != nil {
		t.Fatal(err)
	}
	saved, err := ReadWhitelist(policy.Config{NativeConfDir: filepath.Dir(backup)})
	if err != nil || !SameWhitelist(saved, old) {
		t.Fatalf("backup setting differs: %v", err)
	}
	info, err := os.Stat(backup)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("backup permissions: %v %v", info, err)
	}
	if err := ReplaceWhitelist(conf, old, next); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceWhitelist(conf, old, next); err == nil {
		t.Fatal("stale compare-and-swap succeeded")
	}
	var unrelated string
	if err := db.QueryRow("SELECT value FROM system_config WHERE key='other-key'").Scan(&unrelated); err != nil || unrelated != "keep" {
		t.Fatalf("unrelated key changed: %q: %v", unrelated, err)
	}
}
