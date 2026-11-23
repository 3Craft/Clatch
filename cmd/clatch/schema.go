package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type schemaEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	DefaultPath string `json:"default_path,omitempty"`
	Schema      string `json:"-"`
}

var schemaCatalog = map[string]schemaEntry{
	"install-profile": {
		Name:        "install-profile",
		Description: "Linux installation profile passed to `clatch install plan|apply`",
		Schema: `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://clatch.dev/schemas/install-profile.v1.json",
  "title": "Clatch Linux Install Profile",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "interface", "address", "gateway", "lan"],
  "properties": {
    "schema": { "const": 1, "description": "Profile schema version (must be 1)." },
    "name": { "type": "string", "description": "Optional human-readable gateway name." },
    "description": { "type": "string", "description": "Optional description." },
    "interface": { "type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_-]{0,14}$", "description": "Standalone egress Ethernet interface (not lo)." },
    "address": { "type": "string", "description": "Static IPv4 host address with prefix length (e.g. 192.0.2.10/24)." },
    "gateway": { "type": "string", "format": "ipv4", "description": "Upstream IPv4 default gateway on the connected subnet." },
    "lan": { "type": "array", "minItems": 1, "items": { "type": "string" }, "description": "Canonical IPv4 LAN CIDR prefixes." },
    "public_ipv6": { "const": false, "description": "Must be false (Clatch egress protection is IPv4-only)." },
    "native_mode": { "type": "string", "enum": ["tproxy", "tun"], "description": "Optional mode constraint when using native v2rayA (omit proxy)." },
    "geoip": { "type": "string", "description": "Optional explicit GeoIP database path for native v2rayA profiles." },
    "proxy": {
      "type": "object",
      "additionalProperties": false,
      "required": ["kind", "service", "binary", "config", "policy_source", "dns_address", "dns_port"],
      "description": "Standalone proxy backend configuration. Omit for native v2rayA.",
      "properties": {
        "kind": { "type": "string", "enum": ["xray-core", "mihomo", "v2ray-core"] },
        "mode": { "type": "string", "enum": ["tproxy", "tun"], "default": "tproxy" },
        "service": { "type": "string", "pattern": "^[a-zA-Z0-9][a-zA-Z0-9_.@-]*\\.service$" },
        "binary": { "type": "string", "pattern": "^/" },
        "config": { "type": "string", "pattern": "^/" },
        "policy_source": { "type": "string", "pattern": "^/" },
        "dns_address": { "type": "string", "format": "ipv4", "description": "Loopback IPv4 DNS address (e.g. 127.0.0.1)." },
        "dns_port": { "type": "integer", "minimum": 1, "maximum": 65535 }
      }
    },
    "lan_icmp_diagnostic": {
      "type": "object",
      "additionalProperties": false,
      "required": ["source", "destination"],
      "description": "Optional restricted LAN ICMP diagnostic pair (native TUN only).",
      "properties": {
        "source": { "type": "string", "description": "LAN client /32 IPv4 CIDR." },
        "destination": { "type": "string", "description": "Off-LAN /32 IPv4 CIDR." }
      }
    }
  }
}`,
	},
	"config": {
		Name:        "config",
		Description: "Installed Linux gateway runtime configuration",
		DefaultPath: "/etc/clatch/config.json",
		Schema: `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://clatch.dev/schemas/config.v1.json",
  "title": "Clatch Linux Gateway Config",
  "type": "object",
  "additionalProperties": false,
  "required": ["interface", "diagnostic_uid", "pins", "policy", "lan", "local"],
  "properties": {
    "interface": { "type": "string", "pattern": "^[a-zA-Z0-9_.-]{1,15}$" },
    "diagnostic_uid": { "type": "integer", "minimum": 1 },
    "public_ipv6": { "const": false },
    "native_tun": { "type": "boolean" },
    "pins": { "type": "string", "pattern": "^/" },
    "policy": { "type": "string", "pattern": "^/" },
    "rules_file": { "type": "string", "pattern": "^/" },
    "libexec": { "type": "string" },
    "native_confdir": { "type": "string", "pattern": "^/", "default": "/etc/v2raya" },
    "native_service": { "type": "string", "default": "v2raya" },
    "lan": { "type": "array", "minItems": 1, "items": { "type": "string" } },
    "local": { "type": "array", "minItems": 1, "items": { "type": "string" } },
    "lan_icmp_diagnostic": {
      "type": "object",
      "additionalProperties": false,
      "required": ["source", "destination"],
      "properties": {
        "source": { "type": "string" },
        "destination": { "type": "string" }
      }
    },
    "proxy": {
      "type": "object",
      "additionalProperties": false,
      "required": ["kind", "service", "binary", "config", "policy_source", "dns_address", "dns_port"],
      "properties": {
        "kind": { "type": "string", "enum": ["xray-core", "mihomo", "v2ray-core"] },
        "mode": { "type": "string", "enum": ["tproxy", "tun"] },
        "service": { "type": "string" },
        "binary": { "type": "string", "pattern": "^/" },
        "config": { "type": "string", "pattern": "^/" },
        "policy_source": { "type": "string", "pattern": "^/" },
        "dns_address": { "type": "string", "format": "ipv4" },
        "dns_port": { "type": "integer", "minimum": 1, "maximum": 65535 }
      }
    },
    "probe_routes": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["destination", "via"],
        "properties": {
          "destination": { "type": "string" },
          "via": { "type": "string", "format": "ipv4" }
        }
      }
    }
  }
}`,
	},
	"policy-source": {
		Name:        "policy-source",
		Description: "Approved direct destination CIDR source for standalone Linux or OpenWrt gateways",
		DefaultPath: "/etc/clatch/source-policy.json",
		Schema: `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://clatch.dev/schemas/policy-source.v1.json",
  "title": "Clatch Direct Policy Source",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "networks"],
  "properties": {
    "schema": { "const": 1, "description": "Policy source schema version (must be 1)." },
    "networks": {
      "type": "array",
      "minItems": 1,
      "items": { "type": "string" },
      "description": "Approved direct IPv4 CIDR prefixes (must include LAN ranges on single-arm Linux gateways and proxy server endpoints)."
    },
    "metadata": {
      "type": "object",
      "description": "Optional free-form metadata (e.g. purpose, owner, change ticket)."
    }
  }
}`,
	},
	"health": {
		Name:        "health",
		Description: "Probe defaults read by `clatch health` alongside config.json",
		DefaultPath: "/etc/clatch/health.json",
		Schema: `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://clatch.dev/schemas/health.v1.json",
  "title": "Clatch Health Probe Defaults",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "dns": { "type": "string", "description": "IPv4 resolver address or address:port (defaults to single gateway local IP on port 53)." },
    "expected_exits": {
      "type": "array",
      "items": { "type": "string", "format": "ipv4" },
      "description": "Approved proxy exit IPv4 addresses."
    },
    "conntrack": { "type": "boolean", "description": "Verify conntrack marks / native TUN reply tuples on this gateway." },
    "expect_empty_aaaa": { "type": "boolean", "description": "Require a successful empty AAAA reply for AAAA probes." },
    "direct_url": { "type": "string", "format": "uri", "description": "Override default direct HTTPS probe URL." },
    "proxy_url": { "type": "string", "format": "uri", "description": "Override default proxy exit-IP HTTPS probe URL." },
    "dns_probes": {
      "type": "array",
      "minItems": 1,
      "description": "Override default DNS probe list.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["domain", "type"],
        "properties": {
          "domain": { "type": "string", "minLength": 1 },
          "type": { "type": "string", "enum": ["A", "AAAA"] }
        }
      }
    }
  }
}`,
	},
	"openwrt": {
		Name:        "openwrt",
		Description: "Routed OpenWrt IPv4 WAN guard configuration",
		DefaultPath: "/etc/clatch/openwrt.json",
		Schema: `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://clatch.dev/schemas/openwrt.v1.json",
  "title": "Clatch OpenWrt Gateway Config",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "lan_devices", "lan", "uplinks", "policy"],
  "properties": {
    "schema": { "const": 1 },
    "lan_devices": { "type": "array", "minItems": 1, "items": { "type": "string" } },
    "lan": { "type": "array", "minItems": 1, "items": { "type": "string" } },
    "uplinks": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["network", "device"],
        "properties": {
          "network": { "type": "string", "pattern": "^[A-Za-z0-9_]+$" },
          "device": { "type": "string", "pattern": "^[a-zA-Z0-9_.-]{1,15}$" }
        }
      }
    },
    "policy": { "type": "string", "pattern": "^/" },
    "proxy_device": { "type": "string", "pattern": "^[a-zA-Z0-9_.-]{1,15}$" },
    "unmanaged_egress_devices": { "type": "array", "items": { "type": "string" } }
  }
}`,
	},
}

func runSchema(args []string) (any, error) {
	var options inspectionOptions
	var listOnly bool
	flags := options.flags("schema")
	flags.BoolVar(&listOnly, "list", false, "list available schemas")
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if err := options.resolveFormat(flags); err != nil {
		return nil, err
	}
	if flags.NArg() == 1 && name == "" {
		name = flags.Arg(0)
	} else if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if listOnly || name == "" {
		return schemaListResult(options.json), nil
	}
	entry, ok := schemaCatalog[name]
	if !ok {
		return nil, usageError("unknown schema %q (run `clatch schema --list`)", name)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(entry.Schema), &parsed); err != nil {
		return nil, err
	}
	return inspection{
		value: parsed,
		text:  strings.TrimSpace(entry.Schema) + "\n",
	}, nil
}

func schemaListResult(asJSON bool) inspection {
	names := make([]string, 0, len(schemaCatalog))
	for name := range schemaCatalog {
		names = append(names, name)
	}
	sort.Strings(names)
	items := make([]schemaEntry, 0, len(names))
	var out strings.Builder
	out.WriteString("Available JSON Schemas:\n")
	for _, name := range names {
		entry := schemaCatalog[name]
		items = append(items, entry)
		fmt.Fprintf(&out, "  %-16s %s\n", entry.Name, entry.Description)
	}
	out.WriteString("\nRun `clatch schema <NAME>` to print the full JSON Schema.\n")
	res := inspection{value: map[string]any{"schemas": items}}
	if !asJSON {
		res.text = out.String()
	}
	return res
}
