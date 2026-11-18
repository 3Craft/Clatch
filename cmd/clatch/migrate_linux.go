//go:build linux

package main

import "clatch-gateway/internal/deploy"

func runMigration(args []string) (any, error) {
	if len(args) == 1 && args[0] == "plan" {
		return deploy.Migrate("plan", "")
	}
	if len(args) != 2 {
		return nil, errUsage
	}
	if args[0] == "recover" {
		return deploy.Recover(args[1])
	}
	return deploy.Migrate(args[0], args[1])
}
