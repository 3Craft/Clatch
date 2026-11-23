//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"clatch-gateway/internal/diagnostic"
	"clatch-gateway/internal/guard"
)

var errUsage = errors.New("invalid arguments")

func main() {
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr))
}

func execute(args []string, stdout, stderr io.Writer) int {
	if len(args) >= 3 && args[0] == "diagnostic" &&
		(args[1] == "ping" || args[1] == "traceroute") && args[2] != "--help" && args[2] != "-h" {
		code, err := diagnostic.Run(args[1], args[2], args[3:])
		if err != nil {
			fmt.Fprintf(stderr, "clatch: %v\n", err)
		}
		return code
	}
	if len(args) >= 1 && (args[0] == "--version" || args[0] == "-v") {
		args = append([]string{"version"}, args[1:]...)
	}
	jsonRequested := wantJSON(args)
	if topic, requested := helpTopic(args); requested {
		if jsonRequested {
			if manifest, ok := buildHelpManifest(topic); ok {
				if err := json.NewEncoder(stdout).Encode(manifest); err != nil {
					fmt.Fprintf(stderr, "clatch: %v\n", err)
					return 1
				}
				return 0
			}
		}
		if help := commandHelp(topic); help != "" {
			fmt.Fprint(stdout, help)
			return 0
		}
		err := usageError("unknown command %q", topic)
		writeError(stdout, stderr, topic, err, jsonRequested, false)
		return 2
	}
	result, err := run(args)
	wroteStdout := false
	switch output := result.(type) {
	case inspection:
		var writeErr error
		if !jsonRequested && output.text != "" {
			_, writeErr = io.WriteString(stdout, output.text)
			wroteStdout = true
		} else if output.value != nil {
			writeErr = json.NewEncoder(stdout).Encode(output.value)
			wroteStdout = true
		} else if output.text != "" {
			_, writeErr = io.WriteString(stdout, output.text)
			wroteStdout = true
		}
		err = errors.Join(err, writeErr)
	default:
		if err == nil && result != nil {
			err = json.NewEncoder(stdout).Encode(result)
			wroteStdout = true
		}
	}
	if err != nil {
		topic := topicFor(args)
		writeError(stdout, stderr, topic, err, jsonRequested, wroteStdout)
		if errors.Is(err, errUsage) {
			return 2
		}
		return 1
	}
	return 0
}

func writeError(stdout, stderr io.Writer, topic string, err error, jsonRequested, wroteStdout bool) {
	detail := classifyError(err, topic)
	if jsonRequested && !wroteStdout {
		_ = json.NewEncoder(stdout).Encode(jsonErrorEnvelope{
			OK:      false,
			Passed:  false,
			Command: topic,
			Error:   err.Error(),
			Detail:  detail,
		})
	}
	if errors.Is(err, errUsage) {
		if commandHelp(topic) == "" {
			fmt.Fprintf(stderr, "clatch: unknown command %q. Run clatch --help.\n", topic)
		} else {
			fmt.Fprintf(stderr, "clatch: %v. Run clatch %s --help.\n", err, topic)
		}
		return
	}
	fmt.Fprintf(stderr, "clatch: %v\n", err)
	if !jsonRequested && detail.Hint != "" {
		fmt.Fprintf(stderr, "hint: %s\n", detail.Hint)
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
	case "status":
		return runStatus(args[1:])
	case "health":
		return runHealth(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "explain":
		return runExplain(args[1:])
	case "stats":
		return runStats(args[1:])
	case "init":
		return runInit(args[1:])
	case "schema":
		return runSchema(args[1:])
	case "version":
		return runVersion(args[1:])
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
			return guard.VerifyStandalone(args[1], args[2])
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
