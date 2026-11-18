//go:build linux

package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

var execStart = regexp.MustCompile(`\{\s*path=([^\s;]+)\s*;\s*argv\[\]=([^;]*)\s*;`)

// Preflight binds an installation to the service and proxy settings it will use.
func Preflight(config policy.Config, test bool) (uint16, error) {
	backend := config.Proxy
	info, err := os.Stat(backend.Binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return 0, fmt.Errorf("the configured proxy binary must exist and be executable")
	}
	loadState, err := system.Command("", "systemctl", "show", "--property=LoadState", "--value", backend.Service)
	if err != nil || strings.TrimSpace(string(loadState)) != "loaded" {
		return 0, fmt.Errorf("the configured proxy service must already be loaded")
	}
	command, err := system.Command("", "systemctl", "show", "--property=ExecStart", "--value", backend.Service)
	if err != nil {
		return 0, fmt.Errorf("could not read the configured proxy command")
	}
	commands := execStart.FindAllStringSubmatch(string(command), -1)
	if len(commands) != 1 || commands[0][1] != backend.Binary {
		return 0, fmt.Errorf("proxy service must execute the configured binary directly")
	}
	args := strings.Fields(commands[0][2])
	if len(args) < 2 || args[0] != backend.Binary {
		return 0, fmt.Errorf("invalid proxy service arguments")
	}
	if backend.Kind == "mihomo" {
		return preflightMihomo(config, args[1:], test)
	}
	return preflightCore(backend, args[1:], test)
}

func preflightMihomo(config policy.Config, args []string, test bool) (uint16, error) {
	data, err := ReadMihomo(config)
	if err != nil {
		return 0, err
	}
	values, err := commandValues(args, "-f", "-d")
	if err != nil || values["-f"] != config.Proxy.Config {
		return 0, fmt.Errorf("mihomo service must specify the approved configuration file")
	}
	directory := values["-d"]
	if directory != "" && (!filepath.IsAbs(directory) || filepath.Clean(directory) != directory) {
		return 0, fmt.Errorf("mihomo data directory must be canonical and absolute")
	}
	if test {
		version, err := system.Command("", config.Proxy.Binary, "-v")
		if err != nil || !strings.HasPrefix(strings.ToLower(string(version)), "mihomo ") {
			return 0, fmt.Errorf("unexpected mihomo binary version")
		}
		args := []string{"-t", "-f", config.Proxy.Config}
		if directory != "" {
			args = append(args, "-d", directory)
		}
		if _, err := system.Command("", config.Proxy.Binary, args...); err != nil {
			return 0, fmt.Errorf("mihomo configuration test failed; inspect the proxy configuration locally")
		}
	}
	return data.TPROXYPort, nil
}

func preflightCore(backend *policy.Proxy, args []string, test bool) (uint16, error) {
	if args[0] != "run" {
		return 0, fmt.Errorf("standalone core service must use the run command")
	}
	values, err := commandValues(args[1:], "-c", "-config")
	config := values["-c"]
	if config == "" {
		config = values["-config"]
	}
	if err != nil || len(values) != 1 || config != backend.Config {
		return 0, fmt.Errorf("standalone core service must load the approved configuration file")
	}
	if backend.Kind == "xray-core" {
		if err := validateXrayEnvironment(backend.Service); err != nil {
			return 0, err
		}
	}
	port, err := inspectCoreConfig(backend)
	if err != nil || !test {
		return port, err
	}
	version, err := system.Command("", backend.Binary, "version")
	if err != nil || backend.Kind == "xray-core" && !strings.HasPrefix(string(version), "Xray ") ||
		backend.Kind == "v2ray-core" && (!strings.HasPrefix(string(version), "V2Ray ") || !strings.Contains(string(version), "V2Fly")) {
		return 0, fmt.Errorf("unexpected standalone core binary version")
	}
	testArgs := []string{"test", "-config", backend.Config}
	if backend.Kind == "xray-core" {
		testArgs = []string{"run", "-test", "-config", backend.Config}
	}
	if _, err := system.Command("", backend.Binary, testArgs...); err != nil {
		return 0, fmt.Errorf("standalone core configuration test failed; inspect the proxy configuration locally")
	}
	return port, nil
}

func commandValues(args []string, allowed ...string) (map[string]string, error) {
	values := make(map[string]string, len(allowed))
	for i := 0; i < len(args); i++ {
		key, value, joined := strings.Cut(args[i], "=")
		if !joined && i+1 < len(args) {
			i++
			value = args[i]
		}
		ok := false
		for _, flag := range allowed {
			ok = ok || flag == key
		}
		if !ok || value == "" || values[key] != "" {
			return nil, fmt.Errorf("unsupported or repeated proxy command argument")
		}
		values[key] = value
	}
	return values, nil
}

func validateXrayEnvironment(service string) error {
	for _, property := range []string{"Environment", "EnvironmentFiles", "PassEnvironment"} {
		value, err := system.Command("", "systemctl", "show", "--property="+property, "--value", service)
		if err != nil {
			return fmt.Errorf("could not verify the Xray service environment")
		}
		text := strings.ToLower(strings.TrimSpace(string(value)))
		if property != "Environment" && text != "" || strings.Contains(text, "xray_location_confdir=") ||
			strings.Contains(text, "xray_location_config=") || strings.Contains(text, "xray.location.confdir=") ||
			strings.Contains(text, "xray.location.config=") {
			return fmt.Errorf("Xray service environment can override the approved configuration")
		}
	}
	for _, name := range []string{"xray.location.confdir", "XRAY_LOCATION_CONFDIR", "xray.location.config", "XRAY_LOCATION_CONFIG"} {
		if _, exists := os.LookupEnv(name); exists {
			return fmt.Errorf("installer environment can override the approved Xray configuration")
		}
	}
	return nil
}

type coreStream struct {
	Socket struct {
		TPROXY string `json:"tproxy"`
		Mark   int    `json:"mark"`
	} `json:"sockopt"`
}

func inspectCoreConfig(backend *policy.Proxy) (uint16, error) {
	var config struct {
		Inbounds []struct {
			Protocol string `json:"protocol"`
			Listen   string `json:"listen"`
			Port     uint16 `json:"port"`
			Settings struct {
				Follow  bool   `json:"followRedirect"`
				Network string `json:"network"`
				Allowed string `json:"allowedNetwork"`
			} `json:"settings"`
			Stream coreStream `json:"streamSettings"`
		} `json:"inbounds"`
		Outbounds []struct {
			Protocol string     `json:"protocol"`
			Stream   coreStream `json:"streamSettings"`
		} `json:"outbounds"`
	}
	raw, err := os.ReadFile(backend.Config)
	if err != nil {
		return 0, err
	}
	if err := json.Unmarshal(raw, &config); err != nil || len(config.Outbounds) == 0 {
		return 0, fmt.Errorf("invalid private core configuration or missing outbounds")
	}
	var port uint16
	protocols := map[string]bool{}
	for _, inbound := range config.Inbounds {
		if inbound.Protocol != "dokodemo-door" || !inbound.Settings.Follow || inbound.Stream.Socket.TPROXY != "tproxy" {
			continue
		}
		if inbound.Port < 1024 || port != 0 && port != inbound.Port ||
			inbound.Listen != "" && inbound.Listen != "0.0.0.0" && inbound.Listen != "127.0.0.1" {
			return 0, fmt.Errorf("core TPROXY requires the same local IPv4 port for TCP and UDP")
		}
		port = inbound.Port
		network := inbound.Settings.Network
		if network == "" {
			network = inbound.Settings.Allowed
		}
		if network == "" {
			network = "tcp"
		}
		for protocol := range strings.SplitSeq(network, ",") {
			protocols[strings.TrimSpace(protocol)] = true
		}
	}
	if !protocols["tcp"] || !protocols["udp"] {
		return 0, fmt.Errorf("core requires transparent TCP and UDP inbounds")
	}
	if backend.Kind == "xray-core" {
		for _, outbound := range config.Outbounds {
			if outbound.Protocol != "blackhole" && outbound.Protocol != "loopback" && outbound.Stream.Socket.Mark != 128 {
				return 0, fmt.Errorf("Xray network outbounds must set sockopt.mark=128")
			}
		}
	}
	return port, nil
}
