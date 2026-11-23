//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clatch-gateway/internal/deploy"
	"clatch-gateway/internal/health"
	"clatch-gateway/internal/openwrt"
	"clatch-gateway/internal/policy"
)

func TestVersionTextAndJSON(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		var stdout, stderr bytes.Buffer
		if code := execute(args, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "Clatch ") {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"version", "--json"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("version --json failed: code=%d stderr=%q", code, stderr.String())
	}
	var info versionInfo
	if err := json.Unmarshal(stdout.Bytes(), &info); err != nil || info.Version == "" || info.CLISchemaVersion != 1 {
		t.Fatalf("invalid version JSON: %s (err=%v)", stdout.String(), err)
	}
}

func TestHelpJSONCatalogAndAllCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"help", "--json"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("help --json: code=%d stderr=%q", code, stderr.String())
	}
	var manifest helpManifest
	if err := json.Unmarshal(stdout.Bytes(), &manifest); err != nil {
		t.Fatalf("decode help manifest: %v\n%s", err, stdout.String())
	}
	if manifest.Tool != "clatch" || manifest.CLISchemaVersion != 1 || len(manifest.Commands) < 15 {
		t.Fatalf("unexpected manifest: tool=%q schema=%d commands=%d", manifest.Tool, manifest.CLISchemaVersion, len(manifest.Commands))
	}

	// Verify single command JSON help and human help include flags (e.g. whitelist --apply, --dns-server).
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"whitelist", "--help"}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "--apply") || !strings.Contains(stdout.String(), "--dns-server") {
		t.Fatalf("whitelist --help missing flags: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"help", "whitelist", "--json"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("help whitelist --json failed: code=%d stderr=%q", code, stderr.String())
	}
	var single struct {
		Command commandSpec `json:"command"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &single); err != nil || single.Command.Name != "whitelist" || len(single.Command.Flags) < 5 {
		t.Fatalf("invalid single help JSON: %s (err=%v)", stdout.String(), err)
	}
}

func TestSchemaListAndDefinitions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"schema", "--list", "--json"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("schema --list --json failed: code=%d stderr=%q", code, stderr.String())
	}
	var list struct {
		Schemas []schemaEntry `json:"schemas"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &list); err != nil || len(list.Schemas) != 5 {
		t.Fatalf("unexpected schema list: %s (err=%v)", stdout.String(), err)
	}
	for _, s := range list.Schemas {
		stdout.Reset()
		stderr.Reset()
		if code := execute([]string{"schema", s.Name}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
			t.Fatalf("schema %s failed: code=%d stderr=%q", s.Name, code, stderr.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil || doc["$schema"] == nil {
			t.Fatalf("schema %s invalid JSON: %v", s.Name, err)
		}
	}
}

func TestCLATCHFormatEnvAndJSONErrorEnvelope(t *testing.T) {
	t.Setenv("CLATCH_FORMAT", "json")
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("CLATCH_FORMAT=json version failed: %d", code)
	}
	var info versionInfo
	if err := json.Unmarshal(stdout.Bytes(), &info); err != nil {
		t.Fatalf("expected JSON from CLATCH_FORMAT=json, got: %q", stdout.String())
	}

	// Explicit --format text must override CLATCH_FORMAT=json.
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"version", "--format", "text"}, &stdout, &stderr); code != 0 || !strings.HasPrefix(stdout.String(), "Clatch ") {
		t.Fatalf("--format text override failed: code=%d stdout=%q", code, stdout.String())
	}

	// Usage error in JSON mode emits a valid JSON error envelope on stdout and exit code 2.
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"no-such-cmd", "--json"}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 for unknown command, got %d", code)
	}
	var env jsonErrorEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil || env.OK || env.Detail.Code != "INVALID_ARGUMENTS" {
		t.Fatalf("expected structured JSON error envelope, got: %q (err=%v)", stdout.String(), err)
	}
}

func TestWhitelistFlagOrderingAndValidation(t *testing.T) {
	// Flags after subcommand must work identically to flags before subcommand.
	req1, _, json1, err := parseWhitelistArgs([]string{"--config", "/tmp/c.json", "add", "198.51.100.1/32", "--apply", "--json"})
	if err != nil {
		t.Fatalf("flags before subcommand failed: %v", err)
	}
	req2, _, json2, err := parseWhitelistArgs([]string{"add", "198.51.100.1/32", "--config", "/tmp/c.json", "--dns", "192.0.2.1:5353", "--apply", "--json"})
	if err != nil {
		t.Fatalf("flags after subcommand failed: %v", err)
	}
	if req1.Config != req2.Config || req1.Action != "add" || req2.Action != "add" ||
		len(req2.Inputs) != 1 || req2.Inputs[0] != "198.51.100.1/32" || !req2.Apply || !json1 || !json2 || req2.DNS != "192.0.2.1:5353" {
		t.Fatalf("parsed mismatch: req1=%+v req2=%+v", req1, req2)
	}

	// Invalid flag returns exit code 2 (not 1).
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"whitelist", "show", "--bogus-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 for invalid whitelist flag, got %d (stderr=%q)", code, stderr.String())
	}
}

func TestInitGeneratesValidConfigs(t *testing.T) {
	dir := t.TempDir()

	// 1. init profile for every backend
	for _, tc := range []struct {
		backend string
		mode    string
	}{
		{"xray-core", "tproxy"},
		{"v2ray-core", "tproxy"},
		{"mihomo", "tproxy"},
		{"mihomo", "tun"},
		{"v2raya", "tproxy"},
		{"v2raya", "tun"},
	} {
		outPath := filepath.Join(dir, tc.backend+"-"+tc.mode+".json")
		var stdout, stderr bytes.Buffer
		args := []string{
			"init", "profile",
			"--backend", tc.backend, "--mode", tc.mode,
			"--interface", "ens18", "--address", "192.0.2.10/24", "--gateway", "192.0.2.1", "--lan", "192.0.2.0/24",
			"--output", outPath, "--json",
		}
		if code := execute(args, &stdout, &stderr); code != 0 {
			t.Fatalf("init profile %s/%s failed: code=%d stderr=%q", tc.backend, tc.mode, code, stderr.String())
		}
		checks := deploy.CheckInstallProfile(outPath)
		if len(checks) == 0 || checks[0].ID != "profile.schema" || checks[0].Status != "pass" {
			t.Fatalf("generated profile %s/%s failed schema check: %+v", tc.backend, tc.mode, checks)
		}
	}

	// Refuses overwrite without --force, allows with --force.
	policyPath := filepath.Join(dir, "policy.json")
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"init", "policy", "--networks", "192.0.2.0/24,198.51.100.10/32", "--output", policyPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("init policy failed: code=%d stderr=%q", code, stderr.String())
	}
	if _, err := policy.ReadSource(policyPath); err != nil {
		t.Fatalf("generated policy failed ReadSource: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"init", "policy", "--output", policyPath}, &stdout, &stderr); code != 1 {
		t.Fatalf("expected overwrite refusal without --force, got code=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"init", "policy", "--output", policyPath, "--force"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected overwrite success with --force, got code=%d stderr=%q", code, stderr.String())
	}

	// init health & ReadDefaults validation
	healthPath := filepath.Join(dir, "health.json")
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"init", "health", "--expected-exit", "203.0.113.10", "--conntrack", "--output", healthPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("init health failed: code=%d stderr=%q", code, stderr.String())
	}
	if _, err := health.ReadDefaults(filepath.Join(dir, "config.json")); err != nil {
		t.Fatalf("generated health.json failed ReadDefaults: %v", err)
	}

	// init openwrt & ReadConfig validation
	owrtPath := filepath.Join(dir, "openwrt.json")
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"init", "openwrt", "--policy", policyPath, "--output", owrtPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("init openwrt failed: code=%d stderr=%q", code, stderr.String())
	}
	if _, err := openwrt.ReadConfig(owrtPath); err != nil {
		t.Fatalf("generated openwrt.json failed ReadConfig: %v", err)
	}
}

func TestExplainAndConfigCheckHumanAndJSON(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.json")
	approvedPath := filepath.Join(dir, "approved.json")
	cfgPath := filepath.Join(dir, "config.json")

	if err := os.WriteFile(sourcePath, []byte(`{"schema":1,"networks":["192.0.2.0/24","198.51.100.10/32"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := policy.Config{
		Interface:      "ens18",
		DiagnosticUID:  999,
		Pins:           "/sys/fs/bpf/test",
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
	writeJSONFile(t, approvedPath, approved)
	writeJSONFile(t, cfgPath, cfg)

	// config check human output vs JSON output
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"config", "check", cfgPath}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "Configuration is valid") {
		t.Fatalf("config check text failed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	// explain direct IP (JSON) and blocked IP (text)
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"explain", "198.51.100.10", "--config", cfgPath, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("explain direct JSON failed: code=%d stderr=%q", code, stderr.String())
	}
	var rep explainReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil || rep.Verdict.Decision != "allow_direct" || !rep.Verdict.AllowedDirect {
		t.Fatalf("unexpected explain JSON: %s (err=%v)", stdout.String(), err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"explain", "1.1.1.1", "--config", cfgPath}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "deny_egress") || !strings.Contains(stdout.String(), "To allow") {
		t.Fatalf("explain blocked text failed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	// health human text output on missing DNS (non-JSON default is human text, not raw JSON!)
	cfgMultiLocal := cfg
	cfgMultiLocal.Local = []string{"192.0.2.10/32", "192.0.2.11/32"}
	cfgHealthPath := filepath.Join(dir, "health-cfg.json")
	writeJSONFile(t, cfgHealthPath, cfgMultiLocal)
	stdout.Reset()
	stderr.Reset()
	code := execute([]string{"health", "--config", cfgHealthPath}, &stdout, &stderr)
	if code != 1 || !strings.HasPrefix(stdout.String(), "Clatch health: FAILED") {
		t.Fatalf("health default text failed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	// nft render routes through stdout writer cleanly and supports --json.
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"nft", "render", cfgPath, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("nft render --json failed: code=%d stderr=%q", code, stderr.String())
	}
	var rendered struct {
		Rules string `json:"rules"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rendered); err != nil || !strings.Contains(rendered.Rules, "table inet") {
		t.Fatalf("unexpected nft render JSON: %q (err=%v)", stdout.String(), err)
	}

	// status --strict fails when gateway is unconfigured.
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{"status", "--strict"}, &stdout, &stderr); code != 1 {
		t.Fatalf("status --strict should exit 1 when unconfigured, got %d", code)
	}
}

func TestDoctorHelpersAndJSONOutput(t *testing.T) {
	maj, min, ok := parseKernelVersion("6.12.15-amd64")
	if !ok || maj != 6 || min != 12 {
		t.Fatalf("parseKernelVersion(6.12.15-amd64) = %d.%d (%t)", maj, min, ok)
	}
	maj, min, ok = parseKernelVersion("5.15.0-generic")
	if !ok || maj != 5 || min != 15 {
		t.Fatalf("parseKernelVersion(5.15.0-generic) = %d.%d (%t)", maj, min, ok)
	}

	var stdout, stderr bytes.Buffer
	_ = execute([]string{"doctor", "--json"}, &stdout, &stderr)
	var rep doctorReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil || len(rep.Checks) == 0 {
		t.Fatalf("doctor --json invalid: %q (err=%v)", stdout.String(), err)
	}
}

func TestExampleDeployFilesAreValid(t *testing.T) {
	root := filepath.Join("..", "..", "deploy")
	for _, name := range []string{"standalone.example.json", "mihomo-tun.example.json", "v2raya.example.json"} {
		checks := deploy.CheckInstallProfile(filepath.Join(root, "debian", name))
		if len(checks) == 0 || checks[0].ID != "profile.schema" || checks[0].Status != "pass" {
			t.Fatalf("deploy/debian/%s failed profile schema check: %+v", name, checks)
		}
	}
	if _, err := policy.ReadSource(filepath.Join(root, "debian", "policy.example.json")); err != nil {
		t.Fatalf("deploy/debian/policy.example.json invalid: %v", err)
	}
	if _, err := policy.ReadSource(filepath.Join(root, "openwrt", "policy.example.json")); err != nil {
		t.Fatalf("deploy/openwrt/policy.example.json invalid: %v", err)
	}
	// Validate deploy/debian/health.example.json via temp dir symlink/copy named health.json.
	rawHealth, err := os.ReadFile(filepath.Join(root, "debian", "health.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "health.json"), rawHealth, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := health.ReadDefaults(filepath.Join(tmp, "config.json")); err != nil {
		t.Fatalf("deploy/debian/health.example.json invalid: %v", err)
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
