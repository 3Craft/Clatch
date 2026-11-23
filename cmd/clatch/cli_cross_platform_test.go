package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"clatch-gateway/internal/policy"
)

func TestCrossPlatformOfflineVerifier(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.json")
	approvedPath := filepath.Join(dir, "approved.json")
	cfgPath := filepath.Join(dir, "config.json")
	owrtPath := filepath.Join(dir, "openwrt.json")
	profilePath := filepath.Join(dir, "profile.json")

	if err := os.WriteFile(sourcePath, []byte(`{"schema":1,"networks":["192.0.2.0/24","198.51.100.10/32"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := policy.Config{
		Interface:      "ens18",
		DiagnosticUID:  999,
		Pins:           "/sys/fs/bpf/clatch",
		ApprovedPolicy: approvedPath,
		LAN:            []string{"192.0.2.0/24"},
		Local:          []string{"192.0.2.10/32"},
		Proxy: &policy.Proxy{
			Kind:         "xray-core",
			Mode:         "tproxy",
			Service:      "xray.service",
			Binary:       "/usr/local/bin/xray",
			Config:       "/usr/local/etc/xray/config.json",
			PolicySource: sourcePath,
			DNSAddress:   "127.0.0.1",
			DNSPort:      53,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	src, err := policy.ReadSource(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := cfg.ApprovalFor(src)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteJSON(t, approvedPath, approved)
	mustWriteJSON(t, cfgPath, cfg)

	owrtRaw := `{"schema":1,"lan_devices":["br-lan"],"lan":["192.168.56.0/24"],"uplinks":[{"network":"wan","device":"eth1"}],"policy":"` + sourcePath + `"}`
	if err := os.WriteFile(owrtPath, []byte(owrtRaw), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. version, help --json, schema work on all platforms.
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"version", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version --json: code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"help", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help --json: code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"schema", "install-profile"}, &stdout, &stderr); code != 0 {
		t.Fatalf("schema install-profile: code=%d stderr=%q", code, stderr.String())
	}

	// 2. init profile + doctor --profile work offline.
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"init", "profile", "--backend", "mihomo", "--mode", "tun",
		"--interface", "ens18", "--address", "192.0.2.10/24", "--gateway", "192.0.2.1", "--lan", "192.0.2.0/24",
		"--output", profilePath}, &stdout, &stderr); code != 0 {
		t.Fatalf("init profile: code=%d stderr=%q", code, stderr.String())
	}

	// 3. config check, nft render, explain, openwrt check work offline on macOS & Linux.
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"config", "check", cfgPath}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "Configuration is valid") {
		t.Fatalf("config check: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"nft", "render", cfgPath}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "table inet clatch_guard") || strings.Contains(stdout.String(), "jdn") {
		t.Fatalf("nft render: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"explain", "198.51.100.10", "--config", cfgPath, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("explain: code=%d stderr=%q", code, stderr.String())
	}
	var exp explainReport
	if err := json.Unmarshal(stdout.Bytes(), &exp); err != nil || exp.Verdict.Decision != "allow_direct" {
		t.Fatalf("unexpected explain verdict: %s (err=%v)", stdout.String(), err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"openwrt", "check", owrtPath}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "OpenWrt configuration is valid") {
		t.Fatalf("openwrt check: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	// 4. On non-Linux (e.g. macOS), Linux-only runtime commands give a friendly UNSUPPORTED_PLATFORM error.
	if runtime.GOOS != "linux" {
		for _, args := range [][]string{
			{"status", "--json"},
			{"guard", "verify", "--json"},
			{"install", "plan", profilePath, "--json"},
			{"upgrade", "--json"},
			{"uninstall", "--json"},
			{"stats", "--json"},
			{"explain", "1.1.1.1", "--config", cfgPath, "--live", "--json"},
			{"openwrt", "status", "--json"},
		} {
			stdout.Reset()
			stderr.Reset()
			code := execute(args, &stdout, &stderr)
			var env jsonErrorEnvelope
			if code != 1 || json.Unmarshal(stdout.Bytes(), &env) != nil || env.Detail.Code != "UNSUPPORTED_PLATFORM" ||
				!strings.Contains(env.Detail.Hint, "Available offline on") {
				t.Fatalf("expected UNSUPPORTED_PLATFORM for %v on %s: code=%d stdout=%q stderr=%q",
					args, runtime.GOOS, code, stdout.String(), stderr.String())
			}
		}

		// Human mode also prints a clear hint on stderr.
		stdout.Reset()
		stderr.Reset()
		code := execute([]string{"guard", "verify"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stderr.String(), "requires Linux") || !strings.Contains(stderr.String(), "Available offline") {
			t.Fatalf("expected friendly Linux-only message on %s: code=%d stderr=%q", runtime.GOOS, code, stderr.String())
		}

		// Offline doctor passes cleanly on macOS for a valid profile + config.
		stdout.Reset()
		stderr.Reset()
		if code := execute([]string{"doctor", "--profile", profilePath, "--config", cfgPath, "--openwrt", owrtPath}, &stdout, &stderr); code != 0 ||
			!strings.Contains(stdout.String(), "Clatch doctor: PASSED") {
			t.Fatalf("macOS offline doctor failed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
}

func mustWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
