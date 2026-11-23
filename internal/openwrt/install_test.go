package openwrt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenWrtInstallAndGenerateDHCP(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	cfgPath := filepath.Join(dir, "openwrt.json")
	protoDir := filepath.Join(dir, "proto")

	if err := os.MkdirAll(protoDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`{"schema":1,"networks":["198.18.0.1/32"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfgJSON := `{"schema":1,"lan_devices":["br-lan"],"lan":["192.168.56.0/24"],"uplinks":[{"network":"wan","device":"eth1"}],"policy":"` + policyPath + `"}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0600); err != nil {
		t.Fatal(err)
	}
	dhcpMock := "#!/bin/sh\nproto_dhcp_setup() { :; }\nadd_protocol dhcp\n"
	if err := os.WriteFile(filepath.Join(protoDir, "dhcp.sh"), []byte(dhcpMock), 0755); err != nil {
		t.Fatal(err)
	}

	// Dry run leaves files unwritten.
	dry, err := Install(InstallOptions{ConfigPath: cfgPath, ProtoDir: protoDir, DryRun: true})
	if err != nil || dry.Applied || len(dry.Files) != 2 {
		t.Fatalf("dry run failed: %+v, err=%v", dry, err)
	}
	if _, err := os.Stat(filepath.Join(protoDir, "clatch_static.sh")); !os.IsNotExist(err) {
		t.Fatalf("dry run should not write clatch_static.sh")
	}

	// Real install writes both clatch_static.sh and clatch_dhcp.sh.
	res, err := Install(InstallOptions{ConfigPath: cfgPath, ProtoDir: protoDir, DryRun: false})
	if err != nil || !res.Applied || len(res.Files) != 2 {
		t.Fatalf("install failed: %+v, err=%v", res, err)
	}
	dhcpOut, err := os.ReadFile(filepath.Join(protoDir, "clatch_dhcp.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dhcpOut), "add_protocol dhcp\n") || !strings.Contains(string(dhcpOut), "add_protocol clatch_dhcp") {
		t.Fatalf("unexpected generated clatch_dhcp.sh:\n%s", string(dhcpOut))
	}
}
