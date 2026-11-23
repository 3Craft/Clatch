# Clatch

Fail-closed egress protection for Linux proxy gateways. `nftables` and a pinned
TCX eBPF egress program enforce approved direct destinations independently. The
Linux kernel keeps the TCX link attached across process exits and `nftables`
reloads, preventing direct traffic leaks if the proxy crashes or firewall rules
are flushed.

```
LAN clients ─▶ Proxy (TPROXY / TUN) ─▶ nftables guard ─▶ TCX eBPF egress ─▶ WAN
                                            │                  │
                                     drops unapproved   independent kernel
                                     direct egress      fail-closed LPM check
```

Clatch uses Go for configuration, kernel state, and operations, and C for the
eBPF packet classifier. Project source is licensed under GPL-2.0-only;
dependencies retain their upstream licenses.

## Prerequisites

- **Linux kernel 6.6 or newer** with pinned TCX eBPF support and `bpffs`.
- **Host utilities**: `nft`, `ip`, `tc`, `sysctl` (plus `conntrack` for optional
  `clatch health --conntrack`).
- **Linux systemd gateway target** (Debian 13+, Ubuntu 24.04+/26.04+, etc.):
  static IPv4 configured via either `ifupdown` (`/etc/network/interfaces`) or
  `systemd-networkd` / Netplan, `systemd`, `ping`, `traceroute`, and one
  supported backend (`xray-core`, `v2ray-core`, `mihomo` TPROXY/TUN with
  `tun.device: clatch-tun`, or native `v2rayA` TPROXY/TUN).
- **OpenWrt target** (25.12+): `netifd`, `firewall4`, `ip-full`, `tc-tiny`, and
  optionally `kmod-nft-tproxy` for LAN capture.
- **macOS / non-Linux offline verifier**: `clatch` also builds natively on macOS
  (`make macos`) for offline config/profile validation, nftables rendering, LPM
  explanation, schema export, and starter generation; Linux-only runtime commands
  display a clear platform hint.
- **IPv4-only egress**: public IPv6 egress is intentionally disabled.

Run `clatch doctor` on any target host to verify all prerequisites in one pass.

## Quickstart (Linux systemd gateway)

Prepare your static IPv4 interface (`ifupdown` or `systemd-networkd`) and proxy
service first, then:

```sh
# 1. Generate starter profile and policy files (auto-detects local IPv4 network on Linux)
./clatch-linux-amd64 init profile --backend xray-core --output /root/gateway-profile.json
./clatch-linux-amd64 init policy --output /root/gateway-policy.json

# 2. Edit both files for your proxy paths and approved direct CIDRs, then check readiness
./clatch-linux-amd64 doctor --profile /root/gateway-profile.json

# 3. Review the installation plan (no changes written yet)
./clatch-linux-amd64 install plan /root/gateway-profile.json

# 4. Apply with a persistent local backup directory (arms a 10-minute rollback timer)
./clatch-linux-amd64 install apply /root/gateway-profile.json /root/clatch-install

# 5. Verify guard enforcement and DNS/HTTPS health, then confirm
clatch guard verify
clatch health
clatch install confirm
```

Example templates for all supported backends are provided in `deploy/debian/`:
- [standalone.example.json](deploy/debian/standalone.example.json) (Xray TPROXY)
- [mihomo-tun.example.json](deploy/debian/mihomo-tun.example.json) (Mihomo managed TUN, `device: clatch-tun`)
- [v2raya.example.json](deploy/debian/v2raya.example.json) (Native v2rayA)
- [policy.example.json](deploy/debian/policy.example.json) (Standalone CIDR policy source)
- [health.example.json](deploy/debian/health.example.json) (Health check defaults)

`install apply` leaves an originally stopped proxy service stopped; start it and
verify DNS before confirming. To roll back manually (even after confirmation):

```sh
/root/clatch-install/clatch-recover install rollback /root/clatch-install
```

### Upgrade and Uninstall

```sh
# Safely upgrade /usr/local/sbin/clatch (backs up previous binary and verifies guard)
./clatch-linux-amd64 upgrade

# Preview uninstall actions (dry run), then remove cleanly with --yes
clatch uninstall
clatch uninstall --yes
clatch uninstall --keep-config --yes
```

## Inspect, Diagnose, and Operate

All operational commands default to `/etc/clatch/config.json` (override with
`--config`), print human-readable output by default, and emit structured JSON
with `--json` or `CLATCH_FORMAT=json`.

```sh
clatch status                       # Local service, guard, policy, tunnel & pending state
clatch doctor                       # Full non-destructive host & config readiness checklist
clatch guard verify                 # Verify live nftables ruleset and pinned TCX program
clatch config check                 # Validate config.json and approved policy capacity
clatch explain 1.1.1.1 --live       # Explain why an IP is allowed direct egress or blocked
clatch stats                        # Show TCX allow/deny packet counters
clatch health                       # Run UDP/TCP DNS and direct/proxied HTTPS probes
```

### Health probes (`health.json`)

`clatch health` reads defaults from the sibling `health.json` next to
`config.json` (for example `/etc/clatch/health.json`). Explicit CLI flags
override saved values.

```json
{
  "expected_exits": ["203.0.113.10"],
  "conntrack": true,
  "direct_url": "https://www.baidu.com/",
  "proxy_url": "https://ip.fm/myip",
  "dns_probes": [
    {"domain": "www.baidu.com", "type": "A"},
    {"domain": "ip.fm", "type": "A"},
    {"domain": "www.google.com", "type": "A"},
    {"domain": "www.google.com", "type": "AAAA"}
  ]
}
```

- When `config.json` has one local IPv4 address, `health` uses it on port 53 as
  the default DNS endpoint unless `dns` or `--dns` is set.
- `direct_url`, `proxy_url`, and `dns_probes` are optional; omit them to use
  Clatch's built-in defaults, or customize them for your region and routing rules.
- Run health probes from a host whose traffic follows the gateway under test.
  On the gateway itself, `--conntrack` verifies tracked HTTPS flows (including
  native v2rayA TUN reply tuples).

### Whitelist and policy updates

For native v2rayA gateways, preview changes first and commit with `--apply`
(flags may appear before or after the subcommand):

```sh
clatch whitelist show
clatch whitelist add 198.51.100.10/32
clatch whitelist add 198.51.100.10/32 --apply
clatch whitelist refresh --apply
```

For standalone backends (`xray-core`, `v2ray-core`, `mihomo`), update direct
CIDRs atomically through the old/new intersection:

```sh
clatch policy stage /etc/clatch/config.json /root/policy-tx /root/new-policy.json
clatch policy commit /etc/clatch/config.json /root/policy-tx
```

## CLI Design: Human-Friendly and Agent-Friendly

- **Dual-mode output**: Clean aligned text by default; add `--json`,
  `--format json`, or set `CLATCH_FORMAT=json` for strict machine-readable JSON
  on every command (including structured error envelopes on failure).
- **Self-describing CLI**:
  - `clatch version --json` reports build version, target, and embedded BPF status.
  - `clatch help --json` (and `clatch help COMMAND --json`) exports the full
    command catalog, flags, defaults, mutating/root/platform metadata, and exit codes.
  - `clatch schema --list` and `clatch schema <NAME>` print Draft 2020-12 JSON
    Schemas for `install-profile`, `config`, `policy-source`, `health`, and `openwrt`.
- **Cross-platform offline verifier (macOS)**:
  - Run `config check`, `nft render`, `explain` (offline), `init`, `schema`,
    `doctor`, `openwrt check`, `version`, and `help` natively on macOS before
    deploying to Linux. Linux-only runtime commands exit cleanly with an
    `UNSUPPORTED_PLATFORM` hint.
- **Exit codes**: `0` succeeded (`status` without `--strict` returns `0` even on
  degraded reports; add `--strict` to fail non-healthy states), `1` check or
  operation failed (or unsupported platform), `2` invalid arguments or unknown
  command.

See [docs/agent-guide.md](docs/agent-guide.md) for a concise AI agent playbook.

## OpenWrt

The routed WAN profile uses `netifd`, `firewall4`, `ip-full`, and `tc-tiny` on a
kernel with pinned TCX egress support. It is intentionally IPv4-only. Run the
proxy as a separate service and add each proxy server endpoint to the direct
policy.

1. Install the release binary as `/usr/sbin/clatch`, then generate and validate
   the configuration files:
   ```sh
   clatch init openwrt --lan-device br-lan --lan 192.168.56.0/24 --uplink wan:eth1 --output /etc/clatch/openwrt.json
   clatch init policy --networks 198.18.0.1/32,198.18.0.3/32 --output /etc/clatch/policy.json
   clatch openwrt check
   ```
   See also [deploy/openwrt/openwrt.example.json](deploy/openwrt/openwrt.example.json)
   and [deploy/openwrt/policy.example.json](deploy/openwrt/policy.example.json).
   Use `unmanaged_egress_devices` for interfaces whose egress remains under the
   existing firewall (for example, a primary uplink during a guarded backup trial).
2. Install the embedded `netifd` protocol handlers (`clatch_static.sh` and
   auto-generated `clatch_dhcp.sh`):
   ```sh
   clatch openwrt install --dry-run
   clatch openwrt install
   ```
3. From the local console, configure each external IPv4 interface with
   `proto=clatch_static` or `proto=clatch_dhcp` and its exact UCI `device`.
   Disable separate WAN IPv6 interfaces and flow offloading before bringing up
   guarded uplinks.
4. Inspect and verify:
   ```sh
   clatch openwrt status
   clatch openwrt verify /etc/clatch/openwrt.json wan eth1
   clatch explain 198.18.0.1 --openwrt /etc/clatch/openwrt.json
   clatch stats --openwrt /etc/clatch/openwrt.json
   ```
5. For LAN TCP and UDP capture, install `kmod-nft-tproxy` and configure a
   transparent listener on `127.0.0.1`:
   ```sh
   clatch openwrt tproxy-start /etc/clatch/openwrt.json 12345
   clatch openwrt tproxy-stop
   ```

## Build from Source

Go 1.26 or newer builds both static Linux release binaries (`CGO_ENABLED=0`,
embedded eBPF object) and the macOS offline verifier (`make macos`). Rebuilding
the eBPF object itself requires Clang with a BPF target, Linux UAPI headers, and
`libbpf` headers.

```sh
make -j2          # Linux amd64 & arm64 binaries with embedded eBPF
make macos        # Native macOS offline verifier binary
make test
```

On macOS or a host without the Linux BPF toolchain, build the eBPF object in the
included Debian container first:

```sh
make bpf-container
make -j2 VERSION=v0.1.0
```

Release artifacts are written to `dist/clatch-linux-amd64`,
`dist/clatch-linux-arm64`, and `dist/clatch-darwin-<arch>`.

## Verification and Low-Level Tools

- See [docs/verification.md](docs/verification.md) for the tested backends,
  hardware targets, and packet leak verification matrix.
- Low-level subcommands (`bpf`, `nft render`, `native`, `tproxy`, `managed-tun`)
  remain available for advanced diagnostics and custom wiring. In `clatch bpf`,
  passing `-` as the object path selects the embedded eBPF object.
