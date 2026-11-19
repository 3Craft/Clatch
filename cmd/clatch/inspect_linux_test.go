package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectionHelp(t *testing.T) {
	for _, command := range [][]string{
		{"--help"}, {"status", "--help"}, {"health", "--help"},
		{"guard", "verify", "--help"}, {"config", "check", "--help"}, {"bpf", "--help"},
	} {
		var stdout, stderr bytes.Buffer
		if code := execute(command, &stdout, &stderr); code != 0 || stderr.Len() != 0 ||
			!strings.HasPrefix(stdout.String(), "Usage: clatch ") {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q", command, code, &stdout, &stderr)
		}
	}
}

func TestStatusServiceTextAndJSON(t *testing.T) {
	for _, test := range []struct {
		name, kind, result, active, sub, text string
	}{
		{"completed oneshot", "oneshot", "success", "active", "exited", "startup task completed"},
		{"failed oneshot", "oneshot", "exit-code", "failed", "failed", "failed (failed)"},
		{"stopped oneshot", "oneshot", "success", "inactive", "dead", "inactive (dead)"},
		{"exited non-oneshot", "simple", "success", "active", "exited", "active (exited)"},
		{"running service", "simple", "success", "active", "running", "active (running)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := serviceStatus{Unit: "test.service", Active: test.active, Sub: test.sub,
				kind: test.kind, result: test.result}
			report := statusReport{Services: []serviceStatus{service}}
			if text := report.text(); !strings.Contains(text, "test.service "+test.text+"\n") {
				t.Fatalf("service text output = %q", text)
			}
			raw, err := json.Marshal(service)
			want := `{"unit":"test.service","active":"` + test.active + `","substate":"` + test.sub + `"}`
			if err != nil || string(raw) != want {
				t.Fatalf("service JSON = %s, want %s (error: %v)", raw, want, err)
			}
		})
	}
}

func TestInspectionFailureOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	for _, command := range [][]string{
		{"status", "--config", path, "--json"},
		{"health", "--config", path, "--json"},
		{"guard", "verify", path, "--json"},
		{"config", "check", "--json", path},
	} {
		var stdout, stderr bytes.Buffer
		code := execute(command, &stdout, &stderr)
		var report struct {
			Config string `json:"config"`
			Passed bool   `json:"passed"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || code != 1 ||
			report.Config != path || report.Passed || stderr.Len() == 0 {
			t.Fatalf("%v: exit %d, report %s, stderr %s (decode: %v)", command, code, &stdout, &stderr, err)
		}
	}
	var stdout, stderr bytes.Buffer
	args := []string{"config", "check", path, "--config", path}
	if code := execute(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "clatch config check --help") {
		t.Fatalf("%v: exit %d, stdout %q, stderr %q", args, code, &stdout, &stderr)
	}
}

func TestHealthReadsSavedExitAndLocalDNS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	config := `{"interface":"eth0","diagnostic_uid":123,"pins":"/sys/fs/bpf/test",
		"policy":"/test/approved.json","lan":["192.0.2.0/24"],"local":["192.0.2.1/32","192.0.2.2/32"]}`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "health.json"), []byte(`{"expected_exits":["203.0.113.10"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"health", "--config", path, "--json"}
	code := execute(args, &stdout, &stderr)
	var report struct {
		ExpectedExits []string `json:"expected_exits"`
		Error         string   `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || code != 1 ||
		len(report.ExpectedExits) != 1 || report.ExpectedExits[0] != "203.0.113.10" ||
		!strings.Contains(report.Error, "no DNS endpoint configured") {
		t.Fatalf("exit %d, report %s, stderr %s (decode: %v)", code, &stdout, &stderr, err)
	}
}
