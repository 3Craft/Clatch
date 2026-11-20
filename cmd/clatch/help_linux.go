//go:build linux

package main

import (
	"os"
	"path/filepath"

	"clatch-gateway/internal/policy"
)

const rootHelp = `Usage: clatch COMMAND [options]

Inspect this gateway
  status         Show local guard, proxy, policy, and deployment status
  health         Run DNS and HTTPS probes
  guard verify   Verify nftables and TCX enforcement
  config check   Validate the local configuration and approved policy

Manage a gateway
  install        Install a Debian gateway
  migrate        Adopt an existing Debian gateway
  whitelist      Inspect or change the native v2rayA whitelist
  policy         Stage, commit, or roll back an approved policy
  openwrt        Manage guarded OpenWrt uplinks
  diagnostic     Run restricted ping or traceroute

Advanced commands: bpf, nft, native, tproxy, managed-tun.
Run clatch COMMAND --help for details.
`

var helpText = map[string]string{
	"status": `Usage: clatch status [--config CONFIG] [--json]

Show local Debian gateway status. The default configuration is
` + policy.DefaultConfigPath + `. Use --json for structured output.
`,
	"health": `Usage: clatch health [options]

Run DNS and HTTPS probes. Read defaults from the local configuration and its
sibling health.json. Explicit probe options override saved values.

  --config CONFIG      Gateway config (default ` + policy.DefaultConfigPath + `)
  --dns ADDRESS        IPv4 resolver address or address:port
  --expected-exit IP   Expected proxy exit IPv4 address (repeatable)
  --conntrack          Verify the tracked HTTPS flows on this gateway
  --expect-empty-aaaa  Require a successful empty AAAA response
  --direct-url URL     Direct HTTPS probe (default https://www.baidu.com/)
  --proxy-url URL      Exit address probe (default https://ip.fm/myip)
  --json               Write a JSON report, including failed checks
`,
	"config":       "Usage: clatch config check [CONFIG] [--config CONFIG] [--json]\n",
	"config check": "Usage: clatch config check [CONFIG] [--config CONFIG] [--json]\n\nValidate the local configuration and its approved policy. Default config " + policy.DefaultConfigPath + ".\n",
	"guard":        "Usage: clatch guard verify [CONFIG] [--config CONFIG] [--json]\n       clatch guard ensure CONFIG IFACE\n",
	"guard verify": "Usage: clatch guard verify [CONFIG] [--config CONFIG] [--json]\n\nVerify nftables and TCX. Default config " + policy.DefaultConfigPath + ".\n",
	"guard ensure": "Usage: clatch guard ensure CONFIG IFACE\n\nApply or restore enforcement using the specified trusted interface.\n",
	"install":      "Usage: clatch install plan PROFILE\n       clatch install apply PROFILE BACKUP\n       clatch install confirm|rollback BACKUP\n",
	"migrate":      "Usage: clatch migrate plan\n       clatch migrate apply BACKUP\n       clatch migrate confirm|rollback BACKUP\n",
	"whitelist":    "Usage: clatch whitelist [--config CONFIG] show|add|remove|import|refresh|restore|recover\n       Mutating whitelist commands support preview and explicit --apply.\n",
	"policy":       "Usage: clatch policy stage CONFIG DIRECTORY SOURCE\n       clatch policy commit|rollback CONFIG DIRECTORY\n",
	"openwrt":      "Usage: clatch openwrt prepare|verify CONFIG LOGICAL DEVICE\n       clatch openwrt tproxy-start CONFIG PORT\n       clatch openwrt tproxy-stop\n",
	"diagnostic":   "Usage: clatch diagnostic ping|traceroute CONFIG [options]\n",
	"legacy-guard": "Usage: clatch legacy-guard [--config CONFIG] ACTION\n       Compatibility entry point for installed gateway wrappers.\n",
	"nft":          "Usage: clatch nft render CONFIG [TUN_IFINDEX]\n",
	"native":       "Usage: clatch native inspect|bind|unbind CONFIG\n       clatch native hook --stage STAGE [--transparent-type MODE] [--v2raya-confdir DIR] [--config CONFIG] [--check]\n",
	"tproxy":       "Usage: clatch tproxy start CONFIG [PORT]\n       clatch tproxy stop\n",
	"managed-tun":  "Usage: clatch managed-tun start CONFIG\n       clatch managed-tun stop\n",
	"bpf": `Usage: clatch bpf COMMAND [arguments]

  attach|attach-wan IFACE OBJECT PINS POLICY UID 0 [TUN]
  prepare OBJECT PINS POLICY UID 0 [TUN]
  replace IFACE ACTIVE_PINS NEXT_PINS
  prune IFACE ACTIVE_PINS OLD_PINS
  verify|verify-wan IFACE PINS
  policy PINS POLICY
  stats PINS
  dump PINS
  detach|detach-wan IFACE PINS

Use - as OBJECT to load the eBPF object built into the release binary.
`,
}

func commandHelp(topic string) string {
	if topic == "" {
		return rootHelp
	}
	return helpText[topic]
}

func topicFor(args []string) string {
	if filepath.Base(os.Args[0]) == "guardctl" {
		return "bpf"
	}
	if len(args) > 1 && helpText[args[0]+" "+args[1]] != "" {
		return args[0] + " " + args[1]
	}
	if len(args) == 0 {
		return ""
	}
	return args[0]
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
