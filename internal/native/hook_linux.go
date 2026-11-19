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
	proxyTable   = "v2raya"
	dnsBypass    = "jdn-v2raya-lan-dns-bypass"
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

// ConfigureDNS updates only the native manager's managed DNS bypass and the
// Clatch-owned redirect table. The manager keeps ownership of its other rules.
func ConfigureDNS(config policy.Config, enable, check bool) (uint16, error) {
	var port uint16
	if enable {
		var err error
		port, err = dnsModulePort(config.NativeConfDir)
		if err != nil {
			return 0, err
		}
	}
	var rules strings.Builder
	if !config.NativeTUN {
		handles, err := dnsBypassHandles(port != 0)
		if err != nil {
			return 0, err
		}
		for _, handle := range handles {
			fmt.Fprintf(&rules, "delete rule inet %s prerouting handle %d\n", proxyTable, handle)
		}
		if port != 0 {
			fmt.Fprintf(&rules, `insert rule inet %s prerouting meta nfproto ipv4 iifname != "lo" fib daddr type local meta l4proto { tcp, udp } th dport 53 return comment %q`+"\n", proxyTable, dnsBypass)
		}
	}
	fmt.Fprintf(&rules, "add table inet %[1]s\ndelete table inet %[1]s\n", dnsTable)
	rules.WriteString(renderDNSRedirect(port))
	if _, err := system.Command(rules.String(), "nft", "--check", "-f", "-"); err != nil {
		return 0, err
	}
	if !check {
		if _, err := system.Command(rules.String(), "nft", "-f", "-"); err != nil {
			return 0, err
		}
	}
	return port, nil
}

func dnsBypassHandles(required bool) ([]uint64, error) {
	data, err := system.Command("", "nft", "--json", "list", "tables")
	if err != nil {
		return nil, err
	}
	var tables struct {
		Objects []struct {
			Table struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &tables); err != nil {
		return nil, err
	}
	for _, item := range tables.Objects {
		if item.Table.Family == "inet" && item.Table.Name == proxyTable {
			return listDNSBypassHandles()
		}
	}
	if required {
		return nil, fmt.Errorf("v2rayA did not create its TPROXY table")
	}
	return nil, nil
}

func listDNSBypassHandles() ([]uint64, error) {
	data, err := system.Command("", "nft", "--json", "--handle", "list", "chain", "inet", proxyTable, "prerouting")
	if err != nil {
		return nil, err
	}
	var chain struct {
		Objects []struct {
			Rule struct {
				Handle  uint64 `json:"handle"`
				Comment string `json:"comment"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &chain); err != nil {
		return nil, err
	}
	var handles []uint64
	for _, item := range chain.Objects {
		if item.Rule.Comment == dnsBypass {
			if item.Rule.Handle == 0 {
				return nil, fmt.Errorf("managed DNS bypass has no nft rule handle")
			}
			handles = append(handles, item.Rule.Handle)
		}
	}
	return handles, nil
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
			"ip frag-off & 0x3fff == 0 ct state { new, established } counter meta mark set meta mark | "+TUNBypassMark+" "+
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
%[5]s  iifname %[4]q ip daddr @direct4 counter meta mark set meta mark | %[8]s comment "jdn-native-tun-direct-lan"
 }
 chain output {
  type route hook output priority mangle; policy accept;
  meta l4proto { tcp, udp } th dport 53 counter return comment "jdn-native-tun-dns-host"
  ip daddr @direct4 counter meta mark set meta mark | %[8]s comment "jdn-native-tun-direct-host"
 }
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  oifname %[4]q meta iif 0 ip saddr %[9]s ip daddr @direct4 counter snat ip to %[6]s comment "jdn-native-tun-local-source"
 }
}
add table inet %[7]s
delete table inet %[7]s
`, captureTable, direct4, direct6, config.Interface, diagnostic, local, dnsTable, TUNBypassMark, TUNIPv4)
	output.WriteString(renderDNSRedirect(port))
	return output.String()
}

func renderDNSRedirect(port uint16) string {
	if port == 0 {
		return ""
	}
	return fmt.Sprintf(`table inet %[1]s {
 chain prerouting {
  type nat hook prerouting priority dstnat - 1; policy accept;
  iifname "lo" return
  meta mark & 0x80 == 0x80 return
  meta nfproto ipv4 fib daddr type local meta l4proto { tcp, udp } th dport 53 counter redirect to :%[2]d
 }
}
`, dnsTable, port)
}
