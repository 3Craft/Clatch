//go:build linux

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"clatch-gateway/internal/gateway"
)

func runPolicy(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errUsage
	}
	action := args[0]
	if action != "stage" && action != "commit" && action != "rollback" {
		return nil, usageError("unknown policy action %q (expected stage, commit, or rollback)", action)
	}

	var options inspectionOptions
	var dirFlag, sourceFlag string
	flags := options.flags("policy " + action)
	flags.StringVar(&dirFlag, "dir", "", "policy transaction directory")
	flags.StringVar(&sourceFlag, "source", "", "candidate policy source JSON")

	var positional, flagArgs []string
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if (arg == "--config" || arg == "-config" || arg == "--dir" || arg == "-dir" ||
				arg == "--source" || arg == "-source" || arg == "--format" || arg == "-format") && i+1 < len(args) {
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

	configPath, dir, source := options.config, dirFlag, sourceFlag
	for _, p := range positional {
		if configPath == "" {
			configPath = p
		} else if dir == "" {
			dir = p
		} else if action == "stage" && source == "" {
			source = p
		} else {
			return nil, usageError("unexpected arguments for `policy %s`", action)
		}
	}
	if configPath == "" || dir == "" || (action == "stage" && source == "") {
		return nil, errUsage
	}
	raw, err := policyResult(action, configPath, dir, source, "")
	if err != nil {
		return nil, err
	}
	res := inspection{value: raw}
	if !options.json {
		if m, ok := raw.(map[string]string); ok {
			var out strings.Builder
			fmt.Fprintf(&out, "Policy transaction %s\nTransaction    %s\n", m["state"], m["transaction"])
			if action == "stage" {
				fmt.Fprintf(&out, "Commit         clatch policy commit %s %s\n", configPath, dir)
				fmt.Fprintf(&out, "Rollback       clatch policy rollback %s %s\n", configPath, dir)
			}
			res.text = out.String()
		}
	}
	return res, nil
}

func policyResult(action, config, directory, source, geoIP string) (any, error) {
	status, err := gateway.PolicyTransaction(action, config, directory, source, geoIP)
	if err != nil {
		return nil, err
	}
	return map[string]string{"state": status, "transaction": filepath.Join(directory, "transaction.json")}, nil
}
