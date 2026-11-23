package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"clatch-gateway/internal/policy"
)

type flagSpec struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Default     string `json:"default,omitempty"`
	Repeatable  bool   `json:"repeatable,omitempty"`
	Description string `json:"description"`
}

type commandSpec struct {
	Name         string     `json:"name"`
	Group        string     `json:"group"`
	Summary      string     `json:"summary"`
	Usage        []string   `json:"usage"`
	Description  string     `json:"description,omitempty"`
	Mutating     bool       `json:"mutating"`
	RequiresRoot bool       `json:"requires_root"`
	LinuxOnly    bool       `json:"linux_only,omitempty"`
	Flags        []flagSpec `json:"flags,omitempty"`
	Examples     []string   `json:"examples,omitempty"`
}

type helpManifest struct {
	Tool             string            `json:"tool"`
	Version          string            `json:"version"`
	Platform         string            `json:"platform"`
	CLISchemaVersion int               `json:"cli_schema_version"`
	Environment      map[string]string `json:"environment"`
	ExitCodes        map[string]string `json:"exit_codes"`
	Commands         []commandSpec     `json:"commands"`
}

var exitCodeDocs = map[string]string{
	"0": "Success (for status without --strict, includes degraded/pending reports)",
	"1": "Operation or verification check failed (or unsupported platform)",
	"2": "Invalid CLI arguments or unknown command",
}

var commandCatalog = []commandSpec{
	{
		Name:      "status",
		Group:     "inspect",
		Summary:   "Show local guard, proxy, policy, and deployment status",
		Usage:     []string{"clatch status [--config CONFIG] [--strict] [--json|--format text|json]"},
		LinuxOnly: true,
		Description: "Inspect local Linux gateway state without sending external network probes. " +
			"Default configuration: " + policy.DefaultConfigPath + ".",
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Gateway configuration file"},
			{Name: "--strict", Type: "bool", Description: "Exit with code 1 unless gateway state is healthy"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json (or set CLATCH_FORMAT=json)"},
		},
		Examples: []string{
			"clatch status",
			"clatch status --json",
			"clatch status --strict --config /etc/clatch/config.json",
		},
	},
	{
		Name:      "health",
		Group:     "inspect",
		Summary:   "Run DNS and HTTPS probes",
		Usage:     []string{"clatch health [options]"},
		LinuxOnly: true,
		Description: "Run UDP/TCP DNS probes and direct/proxied HTTPS probes. " +
			"Reads defaults from the gateway config and its sibling health.json. Explicit flags override saved values.",
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Gateway configuration file"},
			{Name: "--dns", Type: "addr[:port]", Description: "IPv4 resolver address or address:port"},
			{Name: "--expected-exit", Type: "ipv4", Repeatable: true, Description: "Expected proxy exit IPv4 address"},
			{Name: "--conntrack", Type: "bool", Description: "Verify tracked HTTPS flows on this gateway"},
			{Name: "--expect-empty-aaaa", Type: "bool", Description: "Require a successful empty AAAA reply"},
			{Name: "--direct-url", Type: "url", Default: "https://www.baidu.com/", Description: "Direct HTTPS probe URL"},
			{Name: "--proxy-url", Type: "url", Default: "https://ip.fm/myip", Description: "Exit-IP HTTPS probe URL"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON report (including failed or skipped probes)"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
		Examples: []string{
			"clatch health",
			"clatch health --json --dns 192.0.2.1 --expected-exit 203.0.113.10",
		},
	},
	{
		Name:    "doctor",
		Group:   "inspect",
		Summary: "Run non-destructive environment, profile, and config readiness checks",
		Usage:   []string{"clatch doctor [--profile FILE] [--config FILE] [--openwrt FILE] [--json]"},
		Description: "On Linux: check kernel TCX readiness (>= 6.6), systemd, network stack (ifupdown or systemd-networkd), " +
			"required utilities, bpffs mount, privileges, and optional profile/config files. " +
			"On macOS/non-Linux: validate install profiles, gateway configs, and OpenWrt configs offline.",
		Flags: []flagSpec{
			{Name: "--profile", Type: "path", Description: "Validate an install profile JSON (and host network alignment on Linux)"},
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Gateway configuration to inspect if present"},
			{Name: "--openwrt", Type: "path", Description: "OpenWrt configuration to validate if present"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON checklist"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
		Examples: []string{
			"clatch doctor",
			"clatch doctor --profile /root/gateway-profile.json --json",
		},
	},
	{
		Name:    "explain",
		Group:   "inspect",
		Summary: "Explain whether an IP address is allowed direct egress or blocked",
		Usage:   []string{"clatch explain IP [--config CONFIG] [--openwrt CONFIG] [--live] [--json]"},
		Description: "Evaluate longest-prefix match against the approved policy (works offline on macOS/Linux) " +
			"and optionally compare against the live Linux kernel TCX trie (--live).",
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Linux gateway configuration"},
			{Name: "--openwrt", Type: "path", Description: "OpenWrt gateway configuration (use instead of --config)"},
			{Name: "--live", Type: "bool", Description: "Also inspect the live kernel TCX LPM trie (Linux root only)"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON verdict"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
		Examples: []string{
			"clatch explain 1.1.1.1",
			"clatch explain 192.0.2.50 --live --json",
			"clatch explain 198.18.0.1 --openwrt /etc/clatch/openwrt.json",
		},
	},
	{
		Name:         "stats",
		Group:        "inspect",
		Summary:      "Show TCX packet allow/deny counters",
		Usage:        []string{"clatch stats [--config CONFIG] [--openwrt CONFIG] [--json]"},
		Description:  "Read per-CPU TCX packet counters for the configured gateway or OpenWrt uplinks.",
		RequiresRoot: true,
		LinuxOnly:    true,
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Gateway configuration"},
			{Name: "--openwrt", Type: "path", Description: "OpenWrt gateway configuration"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON counters"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
		Examples: []string{
			"clatch stats",
			"clatch stats --json",
		},
	},
	{
		Name:      "guard",
		Group:     "inspect",
		Summary:   "Verify or enforce nftables and TCX protection",
		LinuxOnly: true,
		Usage: []string{
			"clatch guard verify [CONFIG] [--config CONFIG] [--json]",
			"clatch guard ensure CONFIG IFACE",
		},
		Description: "Verify or establish both independent guard layers (nftables and pinned TCX).",
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Gateway configuration file (for verify)"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
	},
	{
		Name:         "guard verify",
		Group:        "inspect",
		Summary:      "Verify nftables and TCX enforcement",
		Usage:        []string{"clatch guard verify [CONFIG] [--config CONFIG] [--json]"},
		Description:  "Verify live nftables rules, pinned TCX link, approved policy digest, and TUN binding. Default config " + policy.DefaultConfigPath + ".",
		RequiresRoot: true,
		LinuxOnly:    true,
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Gateway configuration file"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
	},
	{
		Name:         "guard ensure",
		Group:        "advanced",
		Summary:      "Apply or restore guard enforcement on a trusted interface",
		Usage:        []string{"clatch guard ensure CONFIG IFACE"},
		Description:  "Establish or verify both nftables and TCX layers before enabling IPv4 forwarding.",
		Mutating:     true,
		RequiresRoot: true,
		LinuxOnly:    true,
	},
	{
		Name:    "config",
		Group:   "inspect",
		Summary: "Validate a gateway configuration and approved policy (works offline)",
		Usage:   []string{"clatch config check [CONFIG] [--config CONFIG] [--json]"},
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Gateway configuration file"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
	},
	{
		Name:        "config check",
		Group:       "inspect",
		Summary:     "Validate a gateway configuration and approved policy (works offline)",
		Usage:       []string{"clatch config check [CONFIG] [--config CONFIG] [--json]"},
		Description: "Validate a gateway configuration and its approved policy without touching kernel state. Default config " + policy.DefaultConfigPath + ".",
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Gateway configuration file"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
	},
	{
		Name:    "init",
		Group:   "setup",
		Summary: "Generate starter configuration and profile files (works offline)",
		Usage: []string{
			"clatch init profile [--backend xray-core|mihomo|v2ray-core|v2raya] [--mode tproxy|tun] [options]",
			"clatch init policy [--networks CIDR,...] [--output FILE]",
			"clatch init health [--dns ADDR] [--expected-exit IP] [--conntrack] [--output FILE]",
			"clatch init openwrt [--lan-device DEV] [--lan CIDR] [--uplink NET:DEV] [--output FILE]",
		},
		Description: "Generate schema-compliant starter files. On Linux, `init profile` auto-detects local interface, IPv4 CIDR, gateway, and LAN when available.",
		Flags: []flagSpec{
			{Name: "--backend", Type: "string", Default: "xray-core", Description: "Proxy backend: xray-core, mihomo, v2ray-core, or v2raya (profile)"},
			{Name: "--mode", Type: "string", Default: "tproxy", Description: "Interception mode: tproxy or tun (profile)"},
			{Name: "--name", Type: "string", Description: "Gateway profile name (profile)"},
			{Name: "--interface", Type: "string", Description: "Egress Ethernet interface (auto-detected on Linux if omitted)"},
			{Name: "--address", Type: "cidr", Description: "Static IPv4 host CIDR, e.g. 192.0.2.10/24"},
			{Name: "--gateway", Type: "ipv4", Description: "Upstream IPv4 gateway address"},
			{Name: "--lan", Type: "cidr", Repeatable: true, Description: "Protected LAN IPv4 prefix (repeatable)"},
			{Name: "--networks", Type: "cidr", Repeatable: true, Description: "Direct IPv4 CIDR(s), comma-separated or repeatable (policy)"},
			{Name: "--dns", Type: "addr[:port]", Description: "DNS endpoint for health.json (health)"},
			{Name: "--expected-exit", Type: "ipv4", Repeatable: true, Description: "Expected proxy exit IPv4 (health)"},
			{Name: "--conntrack", Type: "bool", Description: "Enable conntrack verification in health.json (health)"},
			{Name: "--lan-device", Type: "string", Repeatable: true, Description: "OpenWrt LAN bridge/device, default br-lan (openwrt)"},
			{Name: "--uplink", Type: "net:dev", Repeatable: true, Description: "OpenWrt uplink mapping, e.g. wan:eth1 (openwrt)"},
			{Name: "--output", Type: "path", Description: "Write output to file instead of stdout"},
			{Name: "--force", Type: "bool", Description: "Overwrite existing file when --output is set"},
			{Name: "--json", Type: "bool", Description: "Wrap result metadata as JSON (when writing to --output)"},
		},
		Examples: []string{
			"clatch init profile --backend xray-core --output /root/gateway-profile.json",
			"clatch init profile --backend mihomo --mode tun",
			"clatch init policy --networks 192.0.2.0/24,198.51.100.10/32 --output /root/gateway-policy.json",
			"clatch init health --expected-exit 203.0.113.10 --conntrack --output /etc/clatch/health.json",
		},
	},
	{
		Name:        "schema",
		Group:       "setup",
		Summary:     "Print JSON Schemas for Clatch configuration files (works offline)",
		Usage:       []string{"clatch schema [--list] [NAME]"},
		Description: "Output Draft 2020-12 JSON Schema definitions for Clatch input files (install-profile, config, policy-source, health, openwrt).",
		Flags: []flagSpec{
			{Name: "--list", Type: "bool", Description: "List available schema names"},
			{Name: "--json", Type: "bool", Description: "Output schema list as JSON"},
		},
		Examples: []string{
			"clatch schema --list",
			"clatch schema install-profile",
			"clatch schema health",
		},
	},
	{
		Name:      "install",
		Group:     "manage",
		Summary:   "Install a Linux gateway with automatic rollback protection",
		LinuxOnly: true,
		Usage: []string{
			"clatch install plan PROFILE [--json]",
			"clatch install apply PROFILE BACKUP [--json]",
			"clatch install confirm [BACKUP] [--json]",
			"clatch install rollback [BACKUP] [--json]",
		},
		Description:  "Plan, apply, confirm, or roll back a systemd Linux Clatch installation (supports ifupdown and systemd-networkd on Linux >= 6.6). `confirm` and `rollback` automatically resolve the active backup from /etc/clatch/clatch-install.json when BACKUP is omitted.",
		Mutating:     true,
		RequiresRoot: true,
		Flags: []flagSpec{
			{Name: "--profile", Type: "path", Description: "Install profile JSON path (alternative to positional PROFILE)"},
			{Name: "--backup", Type: "path", Description: "Absolute backup directory path (alternative to positional BACKUP)"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
		Examples: []string{
			"clatch install plan /root/gateway-profile.json",
			"clatch install apply /root/gateway-profile.json /root/clatch-install",
			"clatch install confirm",
			"clatch install rollback",
		},
	},
	{
		Name:         "upgrade",
		Group:        "manage",
		Summary:      "Upgrade the installed Clatch binary safely with automatic verification",
		Usage:        []string{"clatch upgrade [--config CONFIG] [--backup DIR] [--json]"},
		Description:  "Replace /usr/local/sbin/clatch with the running binary after verifying guard state, backing up the previous binary and rolling back automatically if verification fails.",
		Mutating:     true,
		RequiresRoot: true,
		LinuxOnly:    true,
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Gateway configuration file"},
			{Name: "--backup", Type: "path", Description: "Backup directory for previous binary (default /root/clatch-upgrade-<timestamp>)"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
	},
	{
		Name:         "uninstall",
		Group:        "manage",
		Summary:      "Preview or cleanly remove a Clatch gateway installation",
		Usage:        []string{"clatch uninstall [--config CONFIG] [--keep-config] [--yes] [--json]"},
		Description:  "Without --yes, previews all services, hooks, TCX links, nftables tables, and files that will be removed. Pass --yes to perform removal.",
		Mutating:     true,
		RequiresRoot: true,
		LinuxOnly:    true,
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Gateway configuration file"},
			{Name: "--keep-config", Type: "bool", Description: "Keep /etc/clatch configuration and policy files"},
			{Name: "--yes", Type: "bool", Description: "Execute removal (omit for dry-run preview)"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
	},
	{
		Name:      "whitelist",
		Group:     "manage",
		Summary:   "Inspect or change the native v2rayA whitelist",
		LinuxOnly: true,
		Usage: []string{
			"clatch whitelist show [options]",
			"clatch whitelist add CIDR|IP... [--apply] [options]",
			"clatch whitelist remove CIDR|IP... [--apply] [options]",
			"clatch whitelist import --file PATH|- [--replace] [--apply] [options]",
			"clatch whitelist refresh [--apply] [options]",
			"clatch whitelist restore BACKUP [--apply] [options]",
			"clatch whitelist recover BACKUP [options]",
		},
		Description:  "Preview or atomically apply native v2rayA whitelist changes with SQLite backup and automatic recovery. Flags may appear before or after the subcommand.",
		Mutating:     true,
		RequiresRoot: true,
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: policy.DefaultConfigPath, Description: "Gateway configuration file"},
			{Name: "--apply", Type: "bool", Description: "Commit the previewed change (omit for dry-run preview)"},
			{Name: "--file", Type: "path", Description: "Import whitelist entries from file or - for stdin (import only)"},
			{Name: "--replace", Type: "bool", Description: "Replace existing custom IPs instead of merging (import only)"},
			{Name: "--backups", Type: "path", Default: "/root/backups/gateway", Description: "Private backup root directory"},
			{Name: "--geoip", Type: "path", Description: "Explicit GeoIP database path"},
			{Name: "--confdir", Type: "path", Description: "Override v2rayA configuration directory"},
			{Name: "--service", Type: "string", Description: "Override v2rayA systemd service name"},
			{Name: "--dns-server", Type: "addr[:port]", Description: "IPv4 DNS endpoint for readiness check (alias: --dns)"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
		Examples: []string{
			"clatch whitelist show",
			"clatch whitelist add 198.51.100.10/32",
			"clatch whitelist add 198.51.100.10/32 --apply",
			"clatch whitelist refresh --apply --json",
		},
	},
	{
		Name:      "policy",
		Group:     "manage",
		Summary:   "Stage, commit, or roll back an approved standalone policy",
		LinuxOnly: true,
		Usage: []string{
			"clatch policy stage CONFIG DIRECTORY SOURCE [--json]",
			"clatch policy commit CONFIG DIRECTORY [--json]",
			"clatch policy rollback CONFIG DIRECTORY [--json]",
		},
		Description:  "Run a two-phase policy update through the intersection of old and new CIDRs.",
		Mutating:     true,
		RequiresRoot: true,
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Description: "Gateway configuration path (alternative to positional CONFIG)"},
			{Name: "--dir", Type: "path", Description: "Transaction directory (alternative to positional DIRECTORY)"},
			{Name: "--source", Type: "path", Description: "Candidate policy source JSON (for stage)"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
	},
	{
		Name:    "openwrt",
		Group:   "manage",
		Summary: "Validate, install, and manage guarded OpenWrt uplinks",
		Usage: []string{
			"clatch openwrt check [CONFIG] [--config CONFIG] [--json]",
			"clatch openwrt install [--config CONFIG] [--proto-dir DIR] [--dry-run] [--json]",
			"clatch openwrt status [CONFIG] [--config CONFIG] [--json]",
			"clatch openwrt prepare CONFIG LOGICAL DEVICE [--json]",
			"clatch openwrt verify CONFIG LOGICAL DEVICE [--json]",
			"clatch openwrt tproxy-start CONFIG PORT [--json]",
			"clatch openwrt tproxy-stop [--json]",
		},
		Description:  "Validate OpenWrt configs (`check` works offline on macOS/Linux), install netifd protocol handlers (`install`), inspect status, and manage guarded WAN uplinks.",
		Mutating:     true,
		RequiresRoot: true,
		Flags: []flagSpec{
			{Name: "--config", Type: "path", Default: "/etc/clatch/openwrt.json", Description: "OpenWrt configuration file (for check, status, install)"},
			{Name: "--proto-dir", Type: "path", Default: "/lib/netifd/proto", Description: "Target netifd proto directory (for install)"},
			{Name: "--dry-run", Type: "bool", Description: "Preview protocol handler files without writing (for install)"},
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
	},
	{
		Name:        "diagnostic",
		Group:       "manage",
		Summary:     "Run restricted ping or traceroute",
		Usage:       []string{"clatch diagnostic ping|traceroute CONFIG [options]"},
		Description: "Run ping or traceroute under the restricted diagnostic account allowed by the egress guard.",
		LinuxOnly:   true,
	},
	{
		Name:        "version",
		Group:       "inspect",
		Summary:     "Show Clatch build and CLI schema version",
		Usage:       []string{"clatch version [--json]"},
		Description: "Display Clatch release version, build target, embedded BPF status, and CLI schema version.",
		Flags: []flagSpec{
			{Name: "--json", Type: "bool", Description: "Write structured JSON output"},
			{Name: "--format", Type: "string", Default: "text", Description: "Output format: text or json"},
		},
	},
	{
		Name:        "nft",
		Group:       "advanced",
		Summary:     "Render the single-arm IPv4 nftables guard ruleset (works offline)",
		Usage:       []string{"clatch nft render CONFIG [TUN_IFINDEX] [--json]"},
		Description: "Render the deterministic nftables ruleset from the gateway config and approved policy.",
	},
	{
		Name:      "native",
		Group:     "advanced",
		Summary:   "Inspect or drive native v2rayA integration hooks",
		LinuxOnly: true,
		Usage: []string{
			"clatch native inspect|bind|unbind CONFIG",
			"clatch native hook --stage STAGE [--transparent-type MODE] [--v2raya-confdir DIR] [--config CONFIG] [--check]",
		},
		Mutating:     true,
		RequiresRoot: true,
	},
	{
		Name:         "tproxy",
		Group:        "advanced",
		Summary:      "Start or stop standalone IPv4 TPROXY interception",
		Usage:        []string{"clatch tproxy start CONFIG [PORT]", "clatch tproxy stop"},
		Mutating:     true,
		RequiresRoot: true,
		LinuxOnly:    true,
	},
	{
		Name:         "managed-tun",
		Group:        "advanced",
		Summary:      "Start or stop managed mihomo TUN interception",
		Usage:        []string{"clatch managed-tun start CONFIG", "clatch managed-tun stop"},
		Mutating:     true,
		RequiresRoot: true,
		LinuxOnly:    true,
	},
	{
		Name:      "bpf",
		Group:     "advanced",
		Summary:   "Low-level TCX eBPF link, map, and counter operations",
		LinuxOnly: true,
		Usage: []string{
			"clatch bpf attach|attach-wan IFACE OBJECT PINS POLICY UID 0 [TUN]",
			"clatch bpf prepare OBJECT PINS POLICY UID 0 [TUN]",
			"clatch bpf replace IFACE ACTIVE_PINS NEXT_PINS",
			"clatch bpf prune IFACE ACTIVE_PINS OLD_PINS",
			"clatch bpf verify|verify-wan IFACE PINS",
			"clatch bpf policy PINS POLICY",
			"clatch bpf stats PINS",
			"clatch bpf dump PINS",
			"clatch bpf detach|detach-wan IFACE PINS",
		},
		Description:  "Operate directly on TCX interfaces and bpffs pin directories. Use - as OBJECT to load the embedded eBPF object.",
		Mutating:     true,
		RequiresRoot: true,
	},
}

var commandIndex = func() map[string]commandSpec {
	m := make(map[string]commandSpec, len(commandCatalog))
	for _, spec := range commandCatalog {
		m[spec.Name] = spec
	}
	return m
}()

func buildHelpManifest(topic string) (any, bool) {
	if topic == "" {
		return helpManifest{
			Tool:             "clatch",
			Version:          version,
			Platform:         runtime.GOOS + "/" + runtime.GOARCH,
			CLISchemaVersion: 1,
			Environment: map[string]string{
				"CLATCH_FORMAT": "Default output format when --json/--format is omitted (text or json)",
			},
			ExitCodes: exitCodeDocs,
			Commands:  commandCatalog,
		}, true
	}
	spec, ok := commandIndex[topic]
	if !ok {
		return nil, false
	}
	return map[string]any{
		"tool":               "clatch",
		"version":            version,
		"platform":           runtime.GOOS + "/" + runtime.GOARCH,
		"cli_schema_version": 1,
		"exit_codes":         exitCodeDocs,
		"command":            spec,
	}, true
}

func renderRootHelp() string {
	var out strings.Builder
	out.WriteString("Usage: clatch COMMAND [options]\n\n")
	if runtime.GOOS != "linux" {
		fmt.Fprintf(&out, "Platform note: running offline verifier on %s/%s.\n", runtime.GOOS, runtime.GOARCH)
		out.WriteString("Offline commands: doctor, explain, config check, nft render, init, schema, openwrt check, version, help.\n\n")
	}
	out.WriteString("Inspect & diagnose\n")
	writeGroupHelp(&out, []string{"status", "health", "doctor", "explain", "stats", "guard verify", "config check", "version"})
	out.WriteString("\nSetup & schemas\n")
	writeGroupHelp(&out, []string{"init", "schema"})
	out.WriteString("\nManage a gateway\n")
	writeGroupHelp(&out, []string{"install", "upgrade", "uninstall", "whitelist", "policy", "openwrt", "diagnostic"})
	out.WriteString("\nAdvanced commands: bpf, nft, native, tproxy, managed-tun.\n")
	out.WriteString("Global output options: --json, --format text|json, or CLATCH_FORMAT=json.\n")
	out.WriteString("Run `clatch COMMAND --help` for details, or `clatch help --json` for a machine-readable catalog.\n")
	return out.String()
}

func writeGroupHelp(out *strings.Builder, names []string) {
	for _, name := range names {
		spec, ok := commandIndex[name]
		if !ok {
			continue
		}
		summary := spec.Summary
		if runtime.GOOS != "linux" && spec.LinuxOnly {
			summary += " [Linux only]"
		}
		fmt.Fprintf(out, "  %-14s %s\n", spec.Name, summary)
	}
}

func renderCommandHelp(spec commandSpec) string {
	var out strings.Builder
	for i, u := range spec.Usage {
		if i == 0 {
			fmt.Fprintf(&out, "Usage: %s\n", u)
		} else {
			fmt.Fprintf(&out, "       %s\n", u)
		}
	}
	if spec.Description != "" {
		fmt.Fprintf(&out, "\n%s\n", spec.Description)
	} else if spec.Summary != "" {
		fmt.Fprintf(&out, "\n%s.\n", spec.Summary)
	}
	if spec.LinuxOnly && runtime.GOOS != "linux" {
		fmt.Fprintf(&out, "\nPlatform note: this command requires Linux (current host: %s/%s).\n", runtime.GOOS, runtime.GOARCH)
	}
	if len(spec.Flags) > 0 {
		out.WriteString("\nOptions:\n")
		for _, f := range spec.Flags {
			label := f.Name
			if f.Type != "" && f.Type != "bool" {
				label += " " + strings.ToUpper(f.Type)
			}
			desc := f.Description
			var meta []string
			if f.Default != "" {
				meta = append(meta, "default "+f.Default)
			}
			if f.Repeatable {
				meta = append(meta, "repeatable")
			}
			if len(meta) > 0 {
				desc += " (" + strings.Join(meta, ", ") + ")"
			}
			fmt.Fprintf(&out, "  %-24s %s\n", label, desc)
		}
	}
	if len(spec.Examples) > 0 {
		out.WriteString("\nExamples:\n")
		for _, ex := range spec.Examples {
			fmt.Fprintf(&out, "  %s\n", ex)
		}
	}
	return out.String()
}

func commandHelp(topic string) string {
	if topic == "" {
		return renderRootHelp()
	}
	spec, ok := commandIndex[topic]
	if !ok {
		return ""
	}
	return renderCommandHelp(spec)
}

func topicFor(args []string) string {
	if filepath.Base(os.Args[0]) == "guardctl" {
		return "bpf"
	}
	var words []string
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		words = append(words, arg)
		if len(words) == 2 {
			break
		}
	}
	if len(words) >= 2 {
		if _, ok := commandIndex[words[0]+" "+words[1]]; ok {
			return words[0] + " " + words[1]
		}
	}
	if len(words) == 0 {
		return ""
	}
	return words[0]
}

func helpTopic(args []string) (string, bool) {
	if len(args) == 0 {
		return topicFor(args), true
	}
	if args[0] == "help" {
		return topicFor(args[1:]), true
	}
	for i, arg := range args {
		if arg == "--" {
			break
		}
		if arg == "--help" || arg == "-h" {
			return topicFor(args[:i]), true
		}
	}
	return "", false
}
