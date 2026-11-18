//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"clatch-gateway/internal/gateway"
)

func runWhitelist(args []string) (any, error) {
	flags := flag.NewFlagSet("whitelist", flag.ContinueOnError)
	req := gateway.WhitelistRequest{}
	flags.StringVar(&req.Config, "config", "/etc/jdn-gateway/config.json", "gateway config")
	flags.StringVar(&req.Backups, "backups", "/root/backups/gateway", "private backup root")
	flags.StringVar(&req.GeoIP, "geoip", "", "explicit GeoIP path")
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	args = flags.Args()
	if len(args) == 0 {
		return nil, errUsage
	}
	req.Action, args = args[0], args[1:]
	var file string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--apply":
			req.Apply = true
		case "--replace":
			if req.Action != "import" {
				return nil, errUsage
			}
			req.Replace = true
		case "--file":
			i++
			if req.Action != "import" || i == len(args) || file != "" {
				return nil, errUsage
			}
			file = args[i]
		default:
			req.Inputs = append(req.Inputs, args[i])
		}
	}
	switch req.Action {
	case "show", "refresh":
		if len(req.Inputs) != 0 {
			return nil, errUsage
		}
	case "add", "remove":
		if len(req.Inputs) == 0 {
			return nil, errUsage
		}
	case "restore", "recover":
		if len(req.Inputs) != 1 {
			return nil, errUsage
		}
		req.Backup, req.Inputs = req.Inputs[0], nil
	case "import":
		if file == "" || len(req.Inputs) != 0 {
			return nil, errUsage
		}
		var err error
		req.Inputs, err = whitelistInput(file)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errUsage
	}
	return gateway.Whitelist(req)
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
