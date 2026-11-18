# Implementation verification

The Go CLI and embedded C/eBPF object cross-compile into static Linux amd64
and arm64 binaries. The standalone Go tests exercise canonical CIDRs and the
kernel map ABI parser. Linux builds and static analysis cover both architectures.

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
| OpenWrt 25.12.6 x86/64 and armsr/armv8 virtual machines | Embedded TCX load, inspect, map/counter reads and detach on loopback | Both smoke tests exited successfully |

The packet suite reused the Python reference harness to provide packet
generation, capture and controls. That result establishes loader and
classifier behavior. The takeover tests exercise the Go control path with a
previously configured core. Complete installation and rollback, v2rayA
whitelist transactions, OpenWrt WAN integration and end-to-end fault
acceptance under the final deployment remain open.
