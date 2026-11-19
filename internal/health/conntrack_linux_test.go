package health

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNativeTUNConntrack(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	for name, script := range map[string]string{
		"ip":        `printf '%s\n' "$*" > "$CLATCH_TEST_ARGS/ip.args"; printf '[{"dev":"%s"}]\n' "$CLATCH_TEST_DEVICE"`,
		"conntrack": `printf '%s\n' "$*" > "$CLATCH_TEST_ARGS/conntrack.args"; printf '%s\n' "$CLATCH_TEST_FLOW"`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}

	check := nativeTUNCheck{
		egress: "ens3", tunnel: "tun0", gateway: netip.MustParseAddr("192.168.1.5"),
		direct: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}
	local := netip.MustParseAddrPort("10.0.85.2:41000")
	for _, test := range []struct {
		name, role, peer, route, flow, reply, wantErr string
	}{
		{name: "direct SNAT", role: "direct", peer: "192.0.2.10:443", route: "ens3", flow: "mark=0", reply: "192.168.1.5"},
		{name: "proxy tunnel", role: "proxy", peer: "203.0.113.10:443", route: "tun0", flow: "mark=0", reply: "10.0.85.2"},
		{name: "proxy policy bypass", role: "proxy", peer: "192.0.2.10:443", wantErr: "does not match the proxy role"},
		{name: "proxy on egress", role: "proxy", peer: "203.0.113.10:443", route: "ens3", wantErr: "route via tun0"},
		{name: "no matching reply", role: "proxy", peer: "203.0.113.10:443", route: "tun0", wantErr: "expected conntrack mark 0"},
		{name: "unexpected mark", role: "proxy", peer: "203.0.113.10:443", route: "tun0", flow: "mark=64", wantErr: "expected conntrack mark 0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			argsDir := t.TempDir()
			t.Setenv("CLATCH_TEST_ARGS", argsDir)
			t.Setenv("CLATCH_TEST_DEVICE", test.route)
			t.Setenv("CLATCH_TEST_FLOW", test.flow)
			result := httpCheck{Role: test.role}
			remote := netip.MustParseAddrPort(test.peer)
			err := check.verify(&result, local, remote)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("got %v, want error containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.ReplyDestination.String() != test.reply || !slices.Equal(result.Marks, []uint32{0}) {
				t.Fatalf("unexpected conntrack result: %+v", result)
			}
			wantRoute := "-4 -j route get " + remote.Addr().String() + " from 10.0.85.2 ipproto tcp sport 41000 dport 443"
			wantConntrack := "-L -p tcp -s 10.0.85.2 -d " + remote.Addr().String() + " --sport 41000 --dport 443" +
				" --reply-src " + remote.Addr().String() + " --reply-dst " + test.reply + " --reply-port-src 443 --status ASSURED"
			if test.role == "direct" {
				wantRoute += " mark 0x80"
			} else {
				wantConntrack += " --reply-port-dst 41000"
			}
			for name, want := range map[string]string{"ip.args": wantRoute, "conntrack.args": wantConntrack} {
				args, err := os.ReadFile(filepath.Join(argsDir, name))
				if err != nil || strings.TrimSpace(string(args)) != want {
					t.Fatalf("%s = %q, want %q (error: %v)", name, args, want, err)
				}
			}
		})
	}
}
