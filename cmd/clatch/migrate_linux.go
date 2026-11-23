//go:build linux

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"clatch-gateway/internal/deploy"
)

func runMigration(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errUsage
	}
	action := args[0]
	var options inspectionOptions
	var backupFlag string
	flags := options.flags("migrate " + action)
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
			if (arg == "--backup" || arg == "-backup" || arg == "--format" || arg == "-format" || arg == "--config" || arg == "-config") && i+1 < len(args) {
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

	var backup string
	switch action {
	case "plan":
		if backupFlag != "" || len(positional) != 0 {
			return nil, usageError("`migrate plan` does not accept a backup path")
		}
	case "apply", "recover":
		backup = backupFlag
		if backup == "" && len(positional) == 1 {
			backup = positional[0]
		} else if backup != "" && len(positional) > 0 || len(positional) > 1 {
			return nil, usageError("`migrate %s` takes one backup path", action)
		}
		if backup == "" {
			return nil, usageError("`migrate %s` requires BACKUP", action)
		}
	case "confirm", "rollback":
		backup = backupFlag
		if backup == "" && len(positional) == 1 {
			backup = positional[0]
		} else if backup != "" && len(positional) > 0 || len(positional) > 1 {
			return nil, usageError("`migrate %s` takes at most one backup path", action)
		}
		if backup == "" {
			resolved, err := deploy.PendingBackup("migrate")
			if err != nil {
				return nil, err
			}
			backup = resolved
		}
	default:
		return nil, usageError("unknown migrate action %q", action)
	}

	var result map[string]any
	var err error
	if action == "recover" {
		result, err = deploy.Recover(backup)
	} else {
		result, err = deploy.Migrate(action, backup)
	}
	if err != nil {
		return nil, err
	}
	if action == "apply" && result != nil {
		result["confirm_command"] = fmt.Sprintf("clatch migrate confirm %s", backup)
		result["rollback_command"] = fmt.Sprintf("%s migrate rollback %s", filepath.Join(backup, "clatch-recover"), backup)
	}
	res := inspection{value: result}
	if !options.json {
		res.text = formatMigrateResult(action, backup, result)
	}
	return res, nil
}

func formatMigrateResult(action, backup string, result map[string]any) string {
	var out strings.Builder
	switch action {
	case "plan":
		fmt.Fprintf(&out, "Migration plan ready\nConfiguration  %v\nInterface      %v\nBackend        %v\nSettings ABI   %v bytes\n",
			result["configuration"], result["interface"], result["backend"], result["settings_abi_bytes"])
		fmt.Fprintln(&out, "Next step      clatch migrate apply /root/clatch-migration")
	case "apply":
		fmt.Fprintf(&out, "Migration applied (rollback timer armed)\nBackup         %s\nRollback timer %v\n",
			backup, result["rollback_timer"])
		fmt.Fprintf(&out, "Verify         clatch guard verify --config /etc/jdn-gateway/config.json\n")
		fmt.Fprintf(&out, "Confirm        clatch migrate confirm %s\n", backup)
		fmt.Fprintf(&out, "Rollback       %s migrate rollback %s\n", filepath.Join(backup, "clatch-recover"), backup)
	case "confirm":
		fmt.Fprintf(&out, "Migration confirmed (rollback timer disarmed)\nBackup         %s\n", backup)
	case "rollback", "recover":
		fmt.Fprintf(&out, "Migration rolled back\nBackup         %s\n", backup)
	}
	return out.String()
}
