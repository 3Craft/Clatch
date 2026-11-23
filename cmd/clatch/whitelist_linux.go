//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"clatch-gateway/internal/gateway"
	"clatch-gateway/internal/policy"
)

func runWhitelist(args []string) (any, error) {
	req, file, asJSON, err := parseWhitelistArgs(args)
	if err != nil {
		return nil, err
	}
	if req.Action == "import" {
		req.Inputs, err = whitelistInput(file)
		if err != nil {
			return nil, err
		}
	}
	result, err := gateway.Whitelist(req)
	if err != nil {
		return nil, err
	}
	res := inspection{value: result}
	if !asJSON {
		res.text = formatWhitelistResult(req, result)
	}
	return res, nil
}

// parseWhitelistArgs accepts whitelist flags either before or after the action
// subcommand so both `clatch whitelist --config X add ...` and
// `clatch whitelist add ... --config X --apply` work identically.
func parseWhitelistArgs(args []string) (gateway.WhitelistRequest, string, bool, error) {
	req := gateway.WhitelistRequest{
		Config:  policy.DefaultConfigPath,
		Backups: "/root/backups/gateway",
	}
	var file string
	var formatStr string
	jsonSet := false
	jsonVal := false
	formatSet := false

	var positionals []string
	afterDoubleDash := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if afterDoubleDash {
			positionals = append(positionals, arg)
			continue
		}
		if arg == "--" {
			afterDoubleDash = true
			continue
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}

		name, val, hasEq := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		nextValue := func() (string, error) {
			if hasEq {
				return val, nil
			}
			i++
			if i >= len(args) {
				return "", usageError("flag -%s requires a value", name)
			}
			return args[i], nil
		}

		switch name {
		case "config":
			v, err := nextValue()
			if err != nil {
				return req, "", false, err
			}
			req.Config = v
		case "backups":
			v, err := nextValue()
			if err != nil {
				return req, "", false, err
			}
			req.Backups = v
		case "geoip":
			v, err := nextValue()
			if err != nil {
				return req, "", false, err
			}
			req.GeoIP = v
		case "confdir":
			v, err := nextValue()
			if err != nil {
				return req, "", false, err
			}
			req.ConfDir = v
		case "service":
			v, err := nextValue()
			if err != nil {
				return req, "", false, err
			}
			req.Service = v
		case "dns-server", "dns":
			v, err := nextValue()
			if err != nil {
				return req, "", false, err
			}
			req.DNS = v
		case "file":
			if file != "" {
				return req, "", false, usageError("duplicate --file flag")
			}
			v, err := nextValue()
			if err != nil {
				return req, "", false, err
			}
			file = v
		case "apply":
			if hasEq {
				b, err := parseBoolFlag(name, val)
				if err != nil {
					return req, "", false, err
				}
				req.Apply = b
			} else {
				req.Apply = true
			}
		case "replace":
			if hasEq {
				b, err := parseBoolFlag(name, val)
				if err != nil {
					return req, "", false, err
				}
				req.Replace = b
			} else {
				req.Replace = true
			}
		case "json":
			jsonSet = true
			if hasEq {
				b, err := parseBoolFlag(name, val)
				if err != nil {
					return req, "", false, err
				}
				jsonVal = b
			} else {
				jsonVal = true
			}
		case "format":
			formatSet = true
			v, err := nextValue()
			if err != nil {
				return req, "", false, err
			}
			formatStr = v
		default:
			return req, "", false, usageError("unknown flag %q", arg)
		}
	}

	asJSON := defaultJSONOutput()
	if formatSet {
		switch strings.ToLower(strings.TrimSpace(formatStr)) {
		case "json":
			if jsonSet && !jsonVal {
				return req, "", false, usageError("conflicting --json=false and --format=json")
			}
			asJSON = true
		case "text":
			if jsonSet && jsonVal {
				return req, "", false, usageError("conflicting --json and --format=text")
			}
			asJSON = false
		default:
			return req, "", false, usageError("invalid --format %q (expected text or json)", formatStr)
		}
	} else if jsonSet {
		asJSON = jsonVal
	}

	if len(positionals) == 0 {
		return req, "", false, usageError("missing whitelist action (show, add, remove, import, refresh, restore, recover)")
	}
	req.Action, req.Inputs = positionals[0], positionals[1:]
	if req.Replace && req.Action != "import" {
		return req, "", false, usageError("--replace is only valid with `whitelist import`")
	}
	if file != "" && req.Action != "import" {
		return req, "", false, usageError("--file is only valid with `whitelist import`")
	}

	switch req.Action {
	case "show", "refresh":
		if len(req.Inputs) != 0 {
			return req, "", false, usageError("`whitelist %s` does not accept positional arguments", req.Action)
		}
	case "add", "remove":
		if len(req.Inputs) == 0 {
			return req, "", false, usageError("`whitelist %s` requires at least one IP or CIDR", req.Action)
		}
	case "restore", "recover":
		if len(req.Inputs) != 1 {
			return req, "", false, usageError("`whitelist %s` requires a single backup directory path", req.Action)
		}
		req.Backup, req.Inputs = req.Inputs[0], nil
	case "import":
		if file == "" || len(req.Inputs) != 0 {
			return req, "", false, usageError("`whitelist import` requires --file PATH|- and no positional arguments")
		}
	default:
		return req, "", false, usageError("unknown whitelist action %q", req.Action)
	}
	return req, file, asJSON, nil
}

func parseBoolFlag(name, val string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, usageError("invalid boolean value %q for --%s", val, name)
	}
}

func formatWhitelistResult(req gateway.WhitelistRequest, result map[string]any) string {
	var out strings.Builder
	if recovered, ok := result["recovered"].(string); ok {
		fmt.Fprintf(&out, "Whitelist recovered from %s\n", recovered)
		return out.String()
	}
	applied, _ := result["applied"].(bool)
	unchanged, _ := result["unchanged"].(bool)
	needsRestart, _ := result["needs_restart"].(bool)
	switch {
	case req.Action == "show":
		fmt.Fprintf(&out, "Native v2rayA whitelist\n")
	case applied:
		fmt.Fprintf(&out, "Whitelist %s applied\n", req.Action)
	case unchanged:
		fmt.Fprintf(&out, "Whitelist %s unchanged (already up to date)\n", req.Action)
	default:
		fmt.Fprintf(&out, "Whitelist %s preview (dry run)\n", req.Action)
	}
	fmt.Fprintf(&out, "Configuration  %s\n", req.Config)
	if added, ok := result["add"].([]string); ok && len(added) > 0 {
		fmt.Fprintf(&out, "Add            %s\n", strings.Join(added, ", "))
	}
	if removed, ok := result["remove"].([]string); ok && len(removed) > 0 {
		fmt.Fprintf(&out, "Remove         %s\n", strings.Join(removed, ", "))
	}
	if geoip, ok := result["geoip"].(string); ok && geoip != "" {
		fmt.Fprintf(&out, "GeoIP          %s\n", geoip)
	}
	if loaded, ok := result["loaded_nft_matches_installed_data"].(bool); ok {
		fmt.Fprintf(&out, "Capture sync   %t\n", loaded)
	}
	fmt.Fprintf(&out, "Needs restart  %t\n", needsRestart)
	if backup, ok := result["backup"].(string); ok && backup != "" {
		fmt.Fprintf(&out, "Backup         %s\n", backup)
	}
	if req.Action != "show" && !applied && !unchanged && needsRestart {
		fmt.Fprintln(&out, "Next step      Re-run with --apply to commit this change.")
	}
	return out.String()
}

func whitelistInput(path string) ([]string, error) {
	var input io.Reader = os.Stdin
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		input = file
	}
	const maxImport = 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(input, maxImport+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxImport {
		return nil, fmt.Errorf("whitelist import exceeds 1 MiB")
	}
	var values []string
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
		if err := json.Unmarshal(data, &values); err != nil {
			return nil, err
		}
		return values, nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		if value := strings.TrimSpace(line); value != "" {
			values = append(values, value)
		}
	}
	return values, scanner.Err()
}
