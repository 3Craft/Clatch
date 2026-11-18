# Clatch

Fail-closed egress protection for Linux proxy gateways. nftables and a pinned
TCX egress program enforce the approved direct destinations independently.
The Linux kernel keeps the TCX link attached across process exit and nftables
reloads.

Clatch uses Go for configuration, kernel state and operations. The eBPF packet
classifier is written in C. The project source is GPL-2.0-only. Dependencies retain their upstream licenses.

## Build

Go 1.26 or newer can build both release binaries. The eBPF object requires
Clang with a BPF target, Linux UAPI headers and libbpf's compile-time headers.

```sh
make -j2
make test
```

On macOS or a host without the Linux toolchain, build the eBPF object in the
included Debian container before running the same Go build:

```sh
make bpf-container
make -j2
```

The release files are `dist/clatch-linux-amd64` and `dist/clatch-linux-arm64`.
Both embed the BPF object and are built with CGO disabled. The gateway commands
use the host's `nft`, `ip`, `tc` and `sysctl` utilities.

## Current implementation

- TCX attachment and inspection, complete trie replacement, per-CPU counters,
  and compare-and-swap generation changes on a single pinned link.
- Read and validate existing approved policy snapshots for v2rayA, mihomo,
  Xray and V2Fly. Render the existing single-arm IPv4 nftables guard.
- Verify or establish both guard layers before opening IPv4 forwarding for
  standalone TPROXY and managed mihomo TUN gateways. Adopt existing 8-byte and 12-byte settings ABIs.
- Manage IPv4 TPROXY interception for standalone mihomo, Xray and V2Fly.
  Managed mihomo TUN uses a persistent root-owned device. Each interception
  mode owns its nftables table and reserved routing state.
- Validate v2rayA's live ephemeral TUN identity and approved GeoIP/whitelist
  data. Manage native TUN return authorization and the LAN DNS redirect
  through the v2rayA transparent proxy lifecycle hook.
- Stage policy updates through the intersection of old and new CIDRs. Require
  a matching source and DNS readiness before committing. The v2rayA whitelist
  command previews edits, backs up SQLite and supports recovery and restore.
- Run Debian ping and traceroute through the restricted diagnostic account.
- Migrate an existing Debian 13 gateway with its current configuration,
  approved policy and pinned TCX link. Confirm or roll back the change using
  the migration backup.
- Guard routed OpenWrt IPv4 WAN interfaces before netifd applies a static
  address or starts DHCP. The separate WAN TCX program checks destinations
  after masquerading.

## Migrate an existing Debian gateway

Run the commands on a disposable clone first. Keep the backup on a persistent
local filesystem and use a new absolute path. The plan checks the running
legacy guard, installed interception mode and approved policy.

```sh
./clatch-linux-amd64 migrate plan
./clatch-linux-amd64 migrate apply /root/clatch-migration
gateway-guard verify
clatch migrate confirm /root/clatch-migration
```

The migration arms a systemd rollback timer before replacing the entry
points. Confirm after checking the guard, DNS and expected routes. Use
`/root/clatch-migration/clatch-recover migrate rollback /root/clatch-migration`
to restore the previous entry points, including after confirmation.

## OpenWrt

The routed WAN profile uses netifd, firewall4, `ip-full` and `tc-tiny`. The
kernel must support pinned TCX egress links. The profile is intentionally
IPv4-only. Run the proxy as a separate service and add each proxy endpoint
to the direct policy. Set `proxy_device` only for a TUN device you control
and configure its capture and DNS separately.

Configure the logical uplink and its physical Ethernet device in
`deploy/openwrt/openwrt.example.json`. Use the example policy format for your
approved IPv4 destinations. Install the release binary as `/usr/sbin/clatch`,
the configuration as `/etc/clatch/openwrt.json`, and the policy at the path
given in that configuration. Place `clatch_static.sh` in `/lib/netifd/proto/`.
Generate `clatch_dhcp.sh` from the installed OpenWrt DHCP handler and install
it in the same directory for DHCP uplinks.

```sh
tmp=$(mktemp /lib/netifd/proto/.clatch-dhcp.XXXXXX)
sh generate-dhcp.sh > "$tmp" && chmod 0755 "$tmp" &&
    mv "$tmp" /lib/netifd/proto/clatch_dhcp.sh
```

From the local console, configure each external IPv4 interface with
`proto=clatch_static` or `proto=clatch_dhcp` and its exact UCI `device`.
Disable separate WAN IPv6 interfaces and flow offload before enabling the
guarded uplinks. Check each uplink after bringing network and firewall up.

```sh
clatch openwrt verify /etc/clatch/openwrt.json wan eth1
```

For LAN TCP and UDP capture, install `kmod-nft-tproxy` and configure a
transparent listener on `127.0.0.1`. Start capture after the uplink gates
verify. The direct policy and LAN-local traffic bypass the listener.

```sh
clatch openwrt tproxy-start /etc/clatch/openwrt.json 12345
clatch openwrt tproxy-stop
```

Use these commands in the proxy's service lifecycle to restore capture
after boot. Stop removes the interception rules and leaves WAN enforcement
active.

The [verification report](docs/verification.md) records the tested backends,
hardware targets and failure cases.

## Inspect a compatible snapshot

```sh
./dist/clatch-linux-amd64 config check /etc/jdn-gateway/config.json
./dist/clatch-linux-amd64 nft render /etc/jdn-gateway/config.json
```

The `bpf` subcommands operate on explicit interfaces and bpffs paths. Passing
`-` as the object path selects the embedded BPF object. The guardian's
single-arm policy and the kernel layout originate in the jdnOps
`v2raya/fail-closed` implementation.
