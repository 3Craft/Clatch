# Clatch Gateway

Fail-closed egress protection for Linux proxy gateways. nftables and a pinned
TCX egress program enforce the approved direct destinations independently.
The Linux kernel keeps the TCX link attached across process exit and nftables
reloads.

Clatch uses Go for configuration, kernel state and operations. The eBPF packet
classifier is written in C. The source and binaries are licensed under
GPL-2.0-only.

## Build

Go 1.25 or newer can build both release binaries. The eBPF object requires
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
  standalone TPROXY gateways. Adopt existing 8-byte and 12-byte settings ABIs.
- Manage IPv4 TPROXY interception for standalone mihomo, Xray and V2Fly.
  Interception maintains its own nftables table and reserved routing state.

The installer, policy transaction commands, both TUN lifecycles, and OpenWrt
network startup integration are in development. Testing on an existing
gateway should use a disposable clone until its complete migration and
rollback are verified.

## Inspect a compatible snapshot

```sh
./dist/clatch-linux-amd64 config check /etc/jdn-gateway/config.json
./dist/clatch-linux-amd64 nft render /etc/jdn-gateway/config.json
```

The `bpf` subcommands operate on explicit interfaces and bpffs paths. Passing
`-` as the object path selects the embedded BPF object. The guardian's
single-arm policy and the kernel layout originate in the jdnOps
`v2raya/fail-closed` implementation.
