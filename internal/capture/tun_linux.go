//go:build linux

package capture

import (
	"fmt"

	"clatch-gateway/internal/device"
	"clatch-gateway/internal/gateway"
	"clatch-gateway/internal/policy"
)

var managedTUN = mode{
	table: "clatch_mihomo_tun", priority: "10049", routeDevice: device.ManagedTUN,
	statePath: "/run/clatch-mihomo-tun.json",
}

func StartManagedTUN(configPath string) (state, error) {
	var owner state
	err := gateway.WithLock(func() error {
		gate, err := gateway.OpenStandalone(configPath)
		if err != nil {
			return err
		}
		if !gate.Config.IsTUN() {
			return fmt.Errorf("managed TUN capture requires a mihomo TUN profile")
		}
		if _, err := gate.Verify(); err != nil {
			return err
		}
		identity, err := device.VerifyManaged()
		if err != nil {
			return err
		}
		path, err := resolve(configPath)
		if err != nil {
			return err
		}
		owner = state{
			Mode: "mihomo-managed-tun", Config: path,
			Ifindex: identity.Ifindex, Interface: gate.Config.Interface,
		}
		direct := policy.Elements(gate.Approved.Prefixes, 32)
		return managedTUN.start(owner, renderManagedTUN(direct, gate.Config.Interface), tproxy)
	})
	return owner, err
}

func StopManagedTUN() error {
	return stopMode(managedTUN)
}

func renderManagedTUN(direct, iface string) string {
	return fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
 set direct4 { type ipv4_addr; flags interval; auto-merge; elements = { %[2]s }; }
 chain prerouting {
  type filter hook prerouting priority mangle; policy accept;
  iifname != "%[3]s" return
  meta nfproto != ipv4 return
  meta mark & 0x80 != 0 return
  ip daddr @direct4 return
  meta l4proto { tcp, udp } counter meta mark set 0x40 comment "clatch-tun-route-lan"
 }
 chain output {
  type route hook output priority mangle; policy accept;
  meta nfproto != ipv4 return
  meta mark & 0x80 != 0 return
  ip daddr 127.0.0.0/8 return
  ip daddr @direct4 return
  meta l4proto { tcp, udp } counter meta mark set 0x40 comment "clatch-tun-route-host"
 }
}
`, managedTUN.table, direct, iface)
}
