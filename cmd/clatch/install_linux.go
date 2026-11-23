//go:build linux

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"clatch-gateway/internal/deploy"
)

func runInstall(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errUsage
	}
	action := args[0]
	var options inspectionOptions
	var profileFlag, backupFlag string
	flags := options.flags("install " + action)
	flags.StringVar(&profileFlag, "profile", "", "install profile JSON path")
	flags.StringVar(&backupFlag, "backup", "", "absolute backup directory path")

	var positional, flagArgs []string
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if (arg == "--profile" || arg == "-profile" || arg == "--backup" || arg == "-backup" ||
				arg == "--format" || arg == "-format" || arg == "--config" || arg == "-config") && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		positional = append(positional, arg)
	}
	if err := flags.Parse(flagArgs); err != nil {
		return nil, usageError("%v", err)
	}
	if err := options.resolveFormat(flags); err != nil {
		return nil, err
	}

	var profile, backup string
	switch action {
	case "plan":
		profile = profileFlag
		if profile == "" && len(positional) == 1 {
			profile = positional[0]
		} else if profile != "" && len(positional) > 0 || len(positional) > 1 {
			return nil, usageError("`install plan` takes one profile path")
		}
		if profile == "" {
			return nil, usageError("`install plan` requires a profile path")
		}
	case "apply":
		profile, backup = profileFlag, backupFlag
		for _, p := range positional {
			if profile == "" {
				profile = p
			} else if backup == "" {
				backup = p
			} else {
				return nil, usageError("unexpected arguments for `install apply`")
			}
		}
		if profile == "" || backup == "" {
			return nil, usageError("`install apply` requires PROFILE and BACKUP")
		}
	case "confirm", "rollback", "recover":
		backup = backupFlag
		if backup == "" && len(positional) == 1 {
			backup = positional[0]
		} else if backup != "" && len(positional) > 0 || len(positional) > 1 {
			return nil, usageError("`install %s` takes at most one backup path", action)
		}
		if backup == "" && action != "recover" {
			resolved, err := deploy.PendingBackup("install")
			if err != nil {
				return nil, err
			}
			backup = resolved
		}
		if backup == "" {
			return nil, usageError("`install %s` requires BACKUP", action)
		}
	default:
		return nil, usageError("unknown install action %q", action)
	}

	result, err := deploy.Install(action, profile, backup)
	if err != nil {
		return nil, err
	}
	enrichInstallResult(action, profile, backup, result)
	res := inspection{value: result}
	if !options.json {
		res.text = formatInstallResult(action, profile, backup, result)
	}
	return res, nil
}

func enrichInstallResult(action, profile, backup string, result map[string]any) {
	if result == nil {
		return
	}
	switch action {
	case "plan":
		if _, unchanged := result["unchanged"]; !unchanged {
			result["next_steps"] = []string{
				fmt.Sprintf("clatch install apply %s /root/clatch-install", profile),
			}
		}
	case "apply":
		result["confirm_command"] = fmt.Sprintf("clatch install confirm %s", backup)
		result["rollback_command"] = fmt.Sprintf("%s install rollback %s", filepath.Join(backup, "clatch-recover"), backup)
		result["next_steps"] = []string{
			"clatch guard verify",
			"clatch health",
			fmt.Sprintf("clatch install confirm %s", backup),
		}
	}
}

func formatInstallResult(action, profile, backup string, result map[string]any) string {
	var out strings.Builder
	if unchanged, _ := result["unchanged"].(bool); unchanged {
		fmt.Fprintf(&out, "Clatch installation is unchanged (%v)\nBackup         %v\n", result["state"], result["backup"])
		return out.String()
	}
	switch action {
	case "plan":
		fmt.Fprintf(&out, "Install plan ready\nInterface      %v\nBackend        %v (active=%v)\n",
			result["interface"], result["backend"], result["backend_active"])
		if sha, ok := result["network_sha256"].(string); ok && len(sha) >= 12 {
			fmt.Fprintf(&out, "Policy SHA     %s\n", sha[:12])
		}
		if files, ok := result["files"].([]string); ok {
			fmt.Fprintf(&out, "Managed files  %d file(s)\n", len(files))
		}
		fmt.Fprintf(&out, "Next step      clatch install apply %s /root/clatch-install\n", profile)
	case "apply":
		fmt.Fprintf(&out, "Install applied (rollback timer armed)\nBackup         %s\nRollback timer %v\n",
			backup, result["rollback_timer"])
		if active, ok := result["backend_active"].(bool); ok && !active {
			fmt.Fprintln(&out, "Backend note   Originally stopped backend was left stopped; start it and verify DNS before confirming.")
		}
		fmt.Fprintf(&out, "Verify         clatch guard verify && clatch health\n")
		fmt.Fprintf(&out, "Confirm        clatch install confirm %s\n", backup)
		fmt.Fprintf(&out, "Rollback       %s install rollback %s\n", filepath.Join(backup, "clatch-recover"), backup)
	case "confirm":
		fmt.Fprintf(&out, "Install confirmed (rollback timer disarmed)\nBackup         %s\n", backup)
	case "rollback", "recover":
		fmt.Fprintf(&out, "Install rolled back\nBackup         %s\n", backup)
		if retained, ok := result["protection_retained"].(bool); ok && retained {
			fmt.Fprintln(&out, "Protection     Egress guard retained and IPv4 forwarding kept disabled.")
		}
	}
	return out.String()
}
