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

	"clatch-gateway/internal/diagnostic"
	"clatch-gateway/internal/guard"
)

const usage = `Usage: clatch config check CONFIG
       clatch nft render CONFIG [TUN_IFINDEX]
       clatch guard ensure CONFIG IFACE
       clatch guard verify CONFIG
       clatch tproxy start CONFIG [PORT]
       clatch tproxy stop
       clatch managed-tun start CONFIG
       clatch managed-tun stop
       clatch native inspect|bind|unbind CONFIG
       clatch native hook --stage STAGE [--config CONFIG]
       clatch diagnostic ping|traceroute CONFIG [options]
       clatch health --dns ADDRESS --expected-exit IP [options]
       clatch openwrt prepare|verify CONFIG LOGICAL DEVICE
       clatch openwrt tproxy-start CONFIG PORT | tproxy-stop
       clatch install plan PROFILE | apply PROFILE BACKUP | confirm|rollback BACKUP
       clatch migrate plan | apply|confirm|rollback BACKUP
       clatch whitelist [--config CONFIG] show|add|remove|import|refresh|restore|recover
       clatch policy stage CONFIG DIRECTORY SOURCE
       clatch policy commit|rollback CONFIG DIRECTORY
       clatch bpf COMMAND [arguments]
  attach|attach-wan IFACE OBJECT PINS POLICY UID 0 [TUN]
  prepare OBJECT PINS POLICY UID 0 [TUN]
  replace IFACE ACTIVE_PINS NEXT_PINS
  prune IFACE ACTIVE_PINS OLD_PINS
  verify|verify-wan IFACE PINS
  policy PINS POLICY
  stats PINS
  dump PINS
  detach|detach-wan IFACE PINS

Use - as OBJECT to load the eBPF object built into the release binary.`

var errUsage = errors.New(usage)

func main() {
	args := os.Args[1:]
	if len(args) >= 3 && args[0] == "diagnostic" {
		code, err := diagnostic.Run(args[1], args[2], args[3:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "clatch: %v\n", err)
		}
		os.Exit(code)
	}
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
	case "legacy-guard":
		return runLegacyGuard(args[1:])
	case "tproxy":
		return runCapture(args[1:])
	case "managed-tun":
		return runManagedTUN(args[1:])
	case "native":
		return runNative(args[1:])
	case "policy":
		return runPolicy(args[1:])
	case "whitelist":
		return runWhitelist(args[1:])
	case "health":
		return runHealth(args[1:])
	case "migrate":
		return runMigration(args[1:])
	case "install":
		return runInstall(args[1:])
	case "openwrt":
		return runOpenWrt(args[1:])
	default:
		return nil, errUsage
	}
}

func runBPF(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errUsage
	}
	switch args[0] {
	case "attach", "attach-wan":
		if len(args) == 7 || len(args) == 8 {
			policy, settings, err := arguments(args[4:])
			if err != nil {
				return nil, err
			}
			if args[0] == "attach-wan" {
				return guard.AttachWAN(args[1], args[2], args[3], policy, settings)
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
	case "verify", "verify-wan":
		if len(args) == 3 {
			if args[0] == "verify-wan" {
				return guard.VerifyWAN(args[1], args[2])
			}
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
	case "detach", "detach-wan":
		if len(args) == 3 {
			if args[0] == "detach-wan" {
				return nil, guard.DetachWAN(args[1], args[2])
			}
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
