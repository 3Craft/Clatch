//go:build linux

package native

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

const (
	captureTable = "jdn_v2raya_tun"
	dnsTable     = "jdn_v2raya_lan_dns"
)

func InstallCapture(config policy.Config, approved policy.Approved) error {
	var local netip.Addr
	for _, network := range config.LocalPrefixes {
		if network.Addr().Is4() {
			if local.IsValid() {
				return fmt.Errorf("native TUN expects one local IPv4 address")
			}
			local = network.Addr()
		}
	}
	if !local.IsValid() {
		return fmt.Errorf("native TUN needs a local IPv4 address")
	}
	port, err := dnsModulePort(config.NativeConfDir)
	if err != nil {
		return err
	}
	rules := renderCapture(config, approved, local, port)
	if err := applyCapture(rules); err != nil {
		return err
	}
	_, err = system.Command("", "sysctl", "-q", "-w", "net.ipv4.conf.tun0.rp_filter=0",
		"net.ipv4.conf.tun0.send_redirects=0", "net.ipv4.conf.tun0.accept_redirects=0")
	return err
}

func RemoveCapture() error {
	return applyCapture(fmt.Sprintf("add table inet %[1]s\ndelete table inet %[1]s\nadd table inet %[2]s\ndelete table inet %[2]s\n",
		captureTable, dnsTable))
}

func applyCapture(rules string) error {
	if _, err := system.Command(rules, "nft", "--check", "-f", "-"); err != nil {
		return err
	}
	_, err := system.Command(rules, "nft", "-f", "-")
	return err
}

func dnsModulePort(confdir string) (uint16, error) {
	data, err := os.ReadFile(filepath.Join(confdir, "config.json"))
	if err != nil {
		return 0, err
	}
	var generated struct {
		DNS struct {
			Listener *struct {
				Address string `json:"listen_addr"`
			} `json:"listener"`
		} `json:"dns_module"`
	}
	if err := json.Unmarshal(data, &generated); err != nil {
		return 0, fmt.Errorf("invalid generated v2rayA DNS configuration")
	}
	if generated.DNS.Listener == nil {
		return 0, nil
	}
	listener, err := netip.ParseAddrPort(generated.DNS.Listener.Address)
	if err != nil || !listener.Addr().Is4() || !listener.Addr().IsUnspecified() || listener.Port() == 0 {
		return 0, fmt.Errorf("native DNS module requires a wildcard IPv4 listener")
	}
	return listener.Port(), nil
}

func renderCapture(config policy.Config, approved policy.Approved, local netip.Addr, port uint16) string {
	direct4 := policy.Elements(approved.Prefixes, 32)
	direct6 := ""
	if ipv6 := policy.Elements(approved.Prefixes, 128); ipv6 != "" {
		direct6 = "elements = { " + ipv6 + " };"
	}
	diagnostic := ""
	if config.Diagnostic != nil {
		diagnostic = fmt.Sprintf("  iifname %q ip saddr %s ip daddr %s ip protocol icmp icmp type echo-request icmp code 0 "+
			"ip frag-off & 0x3fff == 0 ct state { new, established } counter meta mark set meta mark | 0x80 "+
			"comment \"jdn-native-tun-lan-icmp-diagnostic\"\n", config.Interface, config.Diagnostic.Source, config.Diagnostic.Destination)
	}
	var output strings.Builder
	fmt.Fprintf(&output, `add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
 set direct4 { type ipv4_addr; flags interval; auto-merge; elements = { %[2]s }; }
 set direct6 { type ipv6_addr; flags interval; auto-merge; %[3]s }
 chain prerouting {
  type filter hook prerouting priority mangle; policy accept;
  iifname %[4]q meta nfproto ipv4 fib daddr type local return
  iifname %[4]q meta l4proto { tcp, udp } th dport 53 counter return comment "jdn-native-tun-dns-lan"
%[5]s  iifname %[4]q ip daddr @direct4 counter meta mark set meta mark | 0x80 comment "jdn-native-tun-direct-lan"
 }
 chain output {
  type route hook output priority mangle; policy accept;
  meta l4proto { tcp, udp } th dport 53 counter return comment "jdn-native-tun-dns-host"
  ip daddr @direct4 counter meta mark set meta mark | 0x80 comment "jdn-native-tun-direct-host"
 }
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  oifname %[4]q meta iif 0 ip saddr 10.0.85.2 ip daddr @direct4 counter snat ip to %[6]s comment "jdn-native-tun-local-source"
 }
}
add table inet %[7]s
delete table inet %[7]s
`, captureTable, direct4, direct6, config.Interface, diagnostic, local, dnsTable)
	if port != 0 {
		fmt.Fprintf(&output, `table inet %[1]s {
 chain prerouting {
  type nat hook prerouting priority dstnat - 1; policy accept;
  iifname "lo" return
  meta mark & 0x80 == 0x80 return
  meta nfproto ipv4 fib daddr type local meta l4proto { tcp, udp } th dport 53 counter redirect to :%[2]d
 }
}
`, dnsTable, port)
	}
	return output.String()
}
