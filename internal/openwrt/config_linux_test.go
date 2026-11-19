package openwrt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnmanagedEgressDevice(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"schema":1,"networks":["192.0.2.1/32"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "openwrt.json")
	config := Config{
		Schema:     1,
		LANDevices: []string{"br-lan"},
		LAN:        []string{"192.168.100.0/24"},
		Uplinks:    []Uplink{{Network: "wan", Device: "eth0"}},
		Policy:     policyPath,
	}
	for _, device := range []string{"eth2", "eth0", "br-lan"} {
		config.UnmanagedEgressDevices = []string{device}
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		loaded, err := ReadConfig(path)
		if device != "eth2" {
			if err == nil {
				t.Fatalf("accepted unmanaged egress on protected interface %s", device)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		rules := loaded.rules()
		if !strings.Contains(rules, `set local_devices { type ifname; elements = { "lo", "br-lan", "eth2" }; }`) ||
			!strings.Contains(rules, `set lan { type ifname; elements = { "br-lan" }; }`) {
			t.Fatalf("unmanaged egress changed the protected LAN ingress set:\n%s", rules)
		}
	}
}
