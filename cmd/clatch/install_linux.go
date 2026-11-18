//go:build linux

package main

import "clatch-gateway/internal/deploy"

func runInstall(args []string) (any, error) {
	if len(args) == 2 {
		switch args[0] {
		case "plan":
			return deploy.Install("plan", args[1], "")
		case "confirm", "rollback", "recover":
			return deploy.Install(args[0], "", args[1])
		}
	}
	if len(args) == 3 && args[0] == "apply" {
		return deploy.Install("apply", args[1], args[2])
	}
	return nil, errUsage
}
