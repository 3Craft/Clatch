# Implementation verification

The Go CLI and embedded C/eBPF object cross-compile into static Linux amd64
and arm64 binaries. The standalone Go tests exercise canonical CIDRs and the
kernel map ABI parser. An amd64 Linux test exercises SQLite compare-and-swap
and backup integrity. Linux builds and static analysis cover both architectures.

| Environment | Exercise | Observed result |
| --- | --- | --- |
| Isolated Debian 13 VM | TCX generations and legacy 8-byte settings upgrade | 12 checks passed, including upgrade and inverse replacement on the same link |
| Five isolated Debian 13 VMs | Existing packet suite using the Go loader | 500 checks passed across v2rayA, mihomo TPROXY, Xray, V2Fly and managed mihomo TUN |
| Three standalone TPROXY clones | Go guard and interception takeover, stop/start and nft drift | Existing link, program and policy verified; all three interception modes resumed |
| Managed mihomo TUN clone | Go guard and TUN routing takeover | Capture stopped and resumed with the same trusted device and TCX link |
| Native v2rayA TUN clone | Go unbind/rebind and manager restart using the Go hook | Same TCX link and approved policy; native interception and LAN DNS tables restored |
| Xray clone | Standalone policy staging, refusal and rollback | The restriction survived startup gate reapplication; a mismatched source prevented commit |
| Xray clone after a real VM reboot | Interrupted standalone policy recovery | Old approved source restored and the Go guard completed before networking started |
| Xray clone with an isolated receiver | Restricted ping and traceroute | Both reached the test receiver; ordinary ping was denied and interrupt left no diagnostic unit |
| Native v2rayA TUN clone | Whitelist add and restore with isolated UDP/TCP DNS replies | The approved digest changed and returned to the original value on the same TCX link. Backups passed SQLite integrity checks. |
| Native v2rayA TUN clone | Whitelist change when DNS times out | Application refused, with the approved policy, TCX link and backup path unchanged. |
| Native v2rayA TUN clone after a real VM reboot | Interrupted whitelist update after the SQLite key changed | Boot recovery restored the original SQLite key and policy, then the native TUN capture matched the original whitelist. |
| Five isolated Debian 13 VMs | Migration and actual restart | All five started with the approved policy. Manual rollback restored v2rayA and mihomo; starting the rollback timer's service restored V2Fly. |
| Five isolated Debian 13 VMs | Migrated egress during backend stop, nftables flush, actual reboot and recovery | Calibrated WAN receivers observed 90 control packets and zero unapproved packets from 3,120 probe attempts. |
| Debian 13 Xray clone without an installed guard | Fresh plan, apply, repeat and confirmation | The plan left gateway files absent. Apply restored the previously active Xray, repeating it returned `unchanged`, and UDP/TCP loopback DNS passed with a LAN-only direct policy. |
| Fresh Debian 13 Xray install | Backend stop, nft reload, nft flush and actual reboot | The calibrated receiver saw all 18 control packets and zero unapproved packets from 192 probe attempts. The approved digest and DNS returned after boot. |
| Fresh Debian 13 Xray install | Manual rollback | The backup executable restored ifupdown, forwarding and nftables enablement, then DNS passed on the restored original Xray service. |
| Fresh Debian 13 install with Xray initially stopped | Systemd timer expiry after a refused confirmation | Original files returned, Xray stayed stopped, forwarding stayed disabled, and both guard layers remained attached. |
| Fresh Debian 13 v2rayA 2.5.13 native TUN clone | Install, confirm, repeat and reboot with the reference gateway's installed binaries and GeoIP | The TUN bound on the same TCX link during startup. The live capture matched the approved data, repeat returned `unchanged`, and the reboot re-established the approved digest and native TUN identity. DNS confirmation used the isolated UDP/TCP fixture. |
| Fresh Debian 13 v2rayA native TUN clone | Rollback with the backend initially stopped and with it initially running | The stopped baseline held forwarding disabled. The running baseline returned with the original forwarding setting and fixture DNS, and installer-owned TCX generations were pruned. |
| Isolated Debian 13 fixture | Application health probe and conntrack | Eight A and two empty AAAA checks over UDP and TCP passed. The application probes reported the expected exit and socket marks, and wrong exit and unexpected empty AAAA were refused. |
| OpenWrt 25.12.6 x86/64 and armsr/armv8 virtual machines | Embedded TCX load, inspect, map/counter reads and detach on loopback | Both smoke tests exited successfully |
| OpenWrt 25.12.6 x86/64 and armsr/armv8 virtual machines | Routed static WAN, SNAT, nftables removal and full nftables flush | Each WAN receiver saw all 72 approved probes and zero of 72 unapproved probes. Removing SNAT exposed the LAN source for the approved probes as expected. |
| OpenWrt 25.12.6 x86/64 and armsr/armv8 virtual machines | Guarded DHCP startup | Both installed the synthetic lease after the gate attached. The x86/64 guest withheld the address when the policy file was absent and recovered when it returned. |
| OpenWrt 25.12.6 x86/64 and armsr/armv8 virtual machines | Reboot with guarded DHCP | Both boot IDs changed. The WAN receivers observed zero unapproved packets from 321 x86/64 and 672 armv8 probe attempts. An approved destination replied after each reboot. |
| OpenWrt 25.12.6 x86/64 and armsr/armv8 virtual machines | Xray TPROXY with an approved upstream SOCKS endpoint | TCP and UDP reached the synthetic origin. Stopping Xray or flushing nftables cut access, and the WAN capture saw zero direct packets to the unapproved destination. Both protocols recovered. |

The initial packet suite used the Python reference harness for packet
generation, capture and controls. The migration acceptance used separate
client and receiver namespaces, sending TCP, UDP and ICMP while the gateway
was down or restarting. Receiver captures were filtered on the receiver's
Ethernet destination to exclude unrelated traffic flooded by the switch.

The Debian tests used copies of existing gateway configurations and local
DNS fixtures where noted. The OpenWrt tests cover a single routed WAN per
guest and a software Ethernet device. Dual WAN failover, OpenWrt TUN
integration, and a physical router comparison remain unverified.
