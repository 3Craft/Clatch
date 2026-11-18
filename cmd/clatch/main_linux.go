//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"clatch-gateway/internal/guard"
)

const usage = `Usage: clatch config check CONFIG
       clatch nft render CONFIG [TUN_IFINDEX]
       clatch guard ensure CONFIG IFACE
       clatch guard verify CONFIG
       clatch tproxy start CONFIG [PORT]
       clatch tproxy stop
       clatch bpf COMMAND [arguments]
  attach IFACE OBJECT PINS POLICY UID 0 [TUN]
  prepare OBJECT PINS POLICY UID 0 [TUN]
  replace IFACE ACTIVE_PINS NEXT_PINS
  prune IFACE ACTIVE_PINS OLD_PINS
  verify IFACE PINS
  policy PINS POLICY
  stats PINS
  dump PINS
  detach IFACE PINS

Use - as OBJECT to load the eBPF object built into the release binary.`

var errUsage = errors.New(usage)

func main() {
	args := os.Args[1:]
	result, err := run(args)
	if err == nil && result != nil {
		err = json.NewEncoder(os.Stdout).Encode(result)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "clatch: %v\n", err)
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func run(args []string) (any, error) {
	if filepath.Base(os.Args[0]) == "guardctl" {
		return runBPF(args)
	}
	if len(args) == 0 {
		return nil, errUsage
	}
	switch args[0] {
	case "bpf":
		return runBPF(args[1:])
	case "config":
		return runConfig(args[1:])
	case "nft":
		return runNFT(args[1:])
	case "guard":
		return runGuard(args[1:])
	case "tproxy":
		return runCapture(args[1:])
	default:
		return nil, errUsage
	}
}

func runBPF(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errUsage
	}
	switch args[0] {
	case "attach":
		if len(args) == 7 || len(args) == 8 {
			policy, settings, err := arguments(args[4:])
			if err != nil {
				return nil, err
			}
			return guard.Attach(args[1], args[2], args[3], policy, settings)
		}
	case "prepare":
		if len(args) == 6 || len(args) == 7 {
			policy, settings, err := arguments(args[3:])
			if err != nil {
				return nil, err
			}
			return guard.Prepare(args[1], args[2], policy, settings)
		}
	case "replace":
		if len(args) == 4 {
			return guard.Replace(args[1], args[2], args[3])
		}
	case "prune":
		if len(args) == 4 {
			return guard.Prune(args[1], args[2], args[3])
		}
	case "verify":
		if len(args) == 3 {
			return guard.Verify(args[1], args[2])
		}
	case "policy":
		if len(args) == 3 {
			policy, err := readPolicy(args[2])
			if err != nil {
				return nil, err
			}
			return nil, guard.UpdatePolicy(args[1], policy)
		}
	case "stats":
		if len(args) == 2 {
			return guard.Stats(args[1])
		}
	case "dump":
		if len(args) == 2 {
			return guard.Dump(args[1])
		}
	case "detach":
		if len(args) == 3 {
			return nil, guard.Detach(args[1], args[2])
		}
	}
	return nil, errUsage
}

func arguments(args []string) (guard.Policy, guard.Settings, error) {
	uid, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil || args[2] != "0" {
		return nil, guard.Settings{}, errors.New("invalid UID or IPv6 flag")
	}
	settings := guard.Settings{DiagnosticUID: uint32(uid)}
	if len(args) == 4 {
		iface, err := net.InterfaceByName(args[3])
		if err != nil {
			return nil, guard.Settings{}, err
		}
		settings.TrustedTUNIfindex = uint32(iface.Index)
	}
	policy, err := readPolicy(args[0])
	return policy, settings, err
}

func readPolicy(path string) (guard.Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return guard.ParsePolicy(f)
}
