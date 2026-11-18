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
- Verify v2rayA's native TPROXY or TUN capture against the approved
  GeoIP/whitelist data. The transparent proxy lifecycle hook manages the
  LAN DNS redirect and authorizes the live TUN device in TUN mode.
- Stage policy updates through the intersection of old and new CIDRs. Require
  a matching source and DNS readiness before committing. The v2rayA whitelist
  command previews edits, backs up SQLite and supports recovery and restore.
- Run Debian ping and traceroute through the restricted diagnostic account.
- Probe UDP/TCP DNS, direct and proxied application requests, the expected
  proxy exit address, and optional conntrack marks with `clatch health`.
- Install a new Debian 13 guard from a static ifupdown profile, with a
  recovery executable and systemd rollback timer in the installation backup.
- Migrate an existing Debian 13 gateway with its current configuration,
  approved policy and pinned TCX link. Confirm or roll back the change using
  the migration backup.
- Guard routed OpenWrt IPv4 WAN interfaces before netifd applies a static
  address or starts DHCP. The separate WAN TCX program checks destinations
  after masquerading.

## Install on Debian 13

Prepare the static IPv4 ifupdown interface and the proxy service first. Set
the proxy configuration and CIDR source in
`deploy/debian/standalone.example.json`. A profile without `proxy` reads the
prepared v2rayA mode and whitelist from its SQLite and GeoIP data. Set
`native_mode` to `tproxy` or `tun` to require a specific mode. The installer
uses the existing proxy credentials and service enablement.

```sh
./clatch-linux-amd64 install plan /root/gateway-profile.json
./clatch-linux-amd64 install apply /root/gateway-profile.json /root/clatch-install
gateway-guard verify
clatch install confirm /root/clatch-install
```

Apply leaves an originally stopped backend stopped. Start it when ready and
verify DNS before confirming. Keep the private backup on a persistent local
filesystem. The recovery command restores the previous installation files.
For an originally stopped backend, recovery retains the egress guard and
holds forwarding disabled.

```sh
/root/clatch-install/clatch-recover install rollback /root/clatch-install
```

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

If a v2rayA package update replaced the running executables, resolve the
drift before migrating. When the GeoIP file has changed too, restore the
copy that matches `geoip_sha256` in the approved policy before restarting
v2rayA. Verify the legacy guard and DNS, then rerun the migration plan.
After migration, keep that approved copy available while using
`gateway-whitelist refresh --apply` to approve the new GeoIP data.

Run the application health check from a host whose traffic follows the
gateway under test. Use an expected exit address for that deployment.
Add `--expect-empty-aaaa` for an IPv4-only DNS policy. `--conntrack` checks
the socket marks when running on the gateway.

```sh
clatch health --dns 192.0.2.1 --expected-exit 203.0.113.10
```

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
