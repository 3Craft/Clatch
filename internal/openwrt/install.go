package openwrt

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"clatch-gateway/internal/system"
)

const staticProtoScript = `#!/bin/sh

. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"

proto_clatch_static_init_config() {
	proto_config_add_string 'ipaddr:ipaddr'
	proto_config_add_string 'netmask:netmask'
	proto_config_add_string 'gateway:ipaddr'
	proto_config_add_array 'dns:list(string)'
	proto_config_add_int 'metric'
	proto_config_add_boolean 'defaultroute:bool'
}

proto_clatch_static_setup() {
	local config="$1"
	local device="$2"
	local ipaddr netmask gateway metric defaultroute dns server
	json_get_vars ipaddr netmask gateway metric defaultroute
	json_get_values dns dns

	[ -n "$ipaddr" ] && [ -n "$device" ] || return 1
	case "$ipaddr" in
		*/*)
			netmask="${ipaddr#*/}"
			ipaddr="${ipaddr%/*}"
			;;
	esac
	[ -n "$netmask" ] || return 1
	/usr/sbin/clatch openwrt prepare /etc/clatch/openwrt.json "$config" "$device" || {
		proto_notify_error "$config" CLATCH_GUARD_FAILED
		return 1
	}

	proto_init_update "$device" 1
	proto_add_ipv4_address "$ipaddr" "$netmask"
	if [ -n "$gateway" ] && [ "$defaultroute" != 0 ]; then
		proto_add_ipv4_route 0.0.0.0 0 "$gateway" "" "$metric"
	fi
	for server in $dns; do
		proto_add_dns_server "$server"
	done
	proto_send_update "$config"
}

proto_clatch_static_teardown() {
	return 0
}

add_protocol clatch_static
`

const dhcpProtoSuffix = `
proto_clatch_dhcp_init_config() {
	proto_dhcp_init_config
}

proto_clatch_dhcp_setup() {
	/usr/sbin/clatch openwrt prepare /etc/clatch/openwrt.json "$1" "$2" || {
		proto_notify_error "$1" CLATCH_GUARD_FAILED
		return 1
	}
	proto_dhcp_setup "$@"
}

proto_clatch_dhcp_renew() {
	/usr/sbin/clatch openwrt prepare /etc/clatch/openwrt.json "$1" "$2" || {
		proto_notify_error "$1" CLATCH_GUARD_FAILED
		return 1
	}
	proto_dhcp_renew "$@"
}

proto_clatch_dhcp_teardown() {
	proto_dhcp_teardown "$@"
}

add_protocol clatch_dhcp
`

// GenerateDHCPProto builds clatch_dhcp.sh from OpenWrt's installed dhcp.sh.
func GenerateDHCPProto(upstreamPath string) ([]byte, error) {
	raw, err := os.ReadFile(upstreamPath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	var out []string
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "add_protocol dhcp" {
			count++
			continue
		}
		out = append(out, line)
	}
	if count != 1 {
		return nil, fmt.Errorf("expected exactly one `add_protocol dhcp` line in %s (found %d)", upstreamPath, count)
	}
	result := strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n" + dhcpProtoSuffix
	return []byte(result), nil
}

// InstallOptions controls `clatch openwrt install`.
type InstallOptions struct {
	ConfigPath string
	ProtoDir   string
	DryRun     bool
}

// InstallResult reports files installed and recommended UCI commands.
type InstallResult struct {
	Applied   bool     `json:"applied"`
	Config    string   `json:"config"`
	ProtoDir  string   `json:"proto_dir"`
	Files     []string `json:"files"`
	NextSteps []string `json:"next_steps"`
}

// Install validates OpenWrt config and installs netifd protocol handlers
// (clatch_static.sh and generated clatch_dhcp.sh) into ProtoDir.
func Install(opts InstallOptions) (InstallResult, error) {
	if opts.ConfigPath == "" {
		opts.ConfigPath = DefaultConfigPath
	}
	if opts.ProtoDir == "" {
		opts.ProtoDir = "/lib/netifd/proto"
	}
	cfg, err := ReadConfig(opts.ConfigPath)
	if err != nil {
		return InstallResult{}, err
	}
	dhcpSource := filepath.Join(opts.ProtoDir, "dhcp.sh")
	dhcpBytes, dhcpErr := GenerateDHCPProto(dhcpSource)

	staticTarget := filepath.Join(opts.ProtoDir, "clatch_static.sh")
	dhcpTarget := filepath.Join(opts.ProtoDir, "clatch_dhcp.sh")

	res := InstallResult{
		Applied:  !opts.DryRun,
		Config:   opts.ConfigPath,
		ProtoDir: opts.ProtoDir,
		Files:    []string{staticTarget},
	}
	if dhcpErr == nil {
		res.Files = append(res.Files, dhcpTarget)
	}
	if !opts.DryRun {
		if err := os.MkdirAll(opts.ProtoDir, 0755); err != nil {
			return res, err
		}
		if err := system.WriteAtomic(staticTarget, []byte(staticProtoScript), 0755); err != nil {
			return res, err
		}
		if dhcpErr == nil {
			if err := system.WriteAtomic(dhcpTarget, dhcpBytes, 0755); err != nil {
				return res, err
			}
		}
	}
	for _, u := range cfg.Uplinks {
		res.NextSteps = append(res.NextSteps,
			fmt.Sprintf("uci set network.%s.proto='clatch_dhcp' # or clatch_static (device=%s)", u.Network, u.Device),
		)
	}
	res.NextSteps = append(res.NextSteps,
		"uci commit network && /etc/init.d/network reload",
		fmt.Sprintf("clatch openwrt status --config %s", opts.ConfigPath),
	)
	return res, nil
}
