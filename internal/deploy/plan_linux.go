//go:build linux

package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"clatch-gateway/internal/gateway"
	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/native"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

const (
	binaryPath      = "/usr/local/sbin/clatch"
	legacyGuardPath = "/usr/local/sbin/gateway-guard"
	configPath      = "/etc/jdn-gateway/config.json"
	guardUnit       = "jdn-gateway-guard.service"
	hookPath        = "/usr/local/libexec/v2raya-lan-dns-hook.py"
	migrationLock   = "/run/lock/clatch-migration.lock"
)

type fileState struct {
	Exists bool        `json:"exists"`
	Mode   os.FileMode `json:"mode"`
	Data   []byte      `json:"data,omitempty"`
}

type change struct {
	Path   string    `json:"path"`
	Before fileState `json:"before"`
	After  fileState `json:"after"`
}

type plan struct {
	Config    policy.Config
	Service   string
	ABI       uint32
	PolicySHA string
	Object    *gateway.BootABI
	Changes   []change
}

func readFile(path string) (fileState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileState{}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fileState{}, fmt.Errorf("migration requires an ordinary file at %s", path)
	}
	data, err := os.ReadFile(path)
	return fileState{Exists: true, Mode: info.Mode().Perm(), Data: data}, err
}

func sameFile(a, b fileState) bool {
	return a.Exists == b.Exists && a.Mode == b.Mode && bytes.Equal(a.Data, b.Data)
}

func statePath(config policy.Config) string {
	return filepath.Join(filepath.Dir(config.ApprovedPolicy), "clatch-deployment.json")
}

func buildPlan() (plan, error) {
	var p plan
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return p, err
	}
	release := "\n" + string(data) + "\n"
	if !strings.Contains(release, "\nID=debian\n") ||
		!strings.Contains(release, "\nVERSION_ID=\"13\"\n") && !strings.Contains(release, "\nVERSION_ID=13\n") {
		return p, fmt.Errorf("existing gateway migration requires Debian 13")
	}
	config, err := policy.ReadConfig(configPath)
	if err != nil {
		return p, err
	}
	if !config.NativeTUN && config.Proxy == nil {
		return p, fmt.Errorf("installed interception mode has no migration adapter")
	}
	for _, name := range []string{"clatch-deployment.json", "clatch-policy-pending.json",
		"pending-transaction.json", "pending-native-tun-generation.json"} {
		path := filepath.Join(filepath.Dir(config.ApprovedPolicy), name)
		if _, err := os.Lstat(path); err == nil {
			return p, fmt.Errorf("finish the existing operation recorded at %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return p, err
		}
	}
	approved, err := config.ReadApproved()
	if err != nil {
		return p, err
	}
	baseline, err := readFile(legacyGuardPath)
	if err != nil {
		return p, err
	}
	if !baseline.Exists || !bytes.Contains(baseline.Data, []byte("/usr/local/libexec/jdn-gateway/gateway-guard.py")) {
		return p, fmt.Errorf("legacy guard entry point does not match a supported installation")
	}
	verified, err := system.Command("", legacyGuardPath, "verify")
	if err != nil {
		return p, fmt.Errorf("legacy guard did not verify: %w", err)
	}
	var status struct {
		SHA string `json:"network_sha256"`
	}
	if err := json.Unmarshal(verified, &status); err != nil || status.SHA != approved.NetworkSHA256 {
		return p, fmt.Errorf("existing guard did not report the approved policy digest")
	}
	p.Config, p.PolicySHA = config, status.SHA
	p.ABI, err = guard.SettingsABI(config.Pins)
	if err != nil {
		return p, err
	}
	for _, unit := range []string{guardUnit, "nftables.service", "networking.service"} {
		if _, err := system.Command("", "systemctl", "is-active", "--quiet", unit); err != nil {
			return p, err
		}
	}
	if config.NativeTUN {
		p.Service = strings.TrimSuffix(config.NativeService, ".service") + ".service"
		if err := native.CheckApproved(config, approved); err != nil {
			return p, err
		}
		if err := native.VerifyCapture(config, approved); err != nil {
			return p, err
		}
	} else {
		p.Service = config.Proxy.Service
		if err := config.CheckSource(approved); err != nil {
			return p, err
		}
	}
	if _, err := system.Command("", "systemctl", "is-active", "--quiet", p.Service); err != nil {
		return p, err
	}
	if p.ABI == 8 {
		if config.IsTUN() {
			return p, fmt.Errorf("TUN configuration cannot use the legacy settings ABI")
		}
		libexec := config.Libexec
		if libexec == "" {
			libexec = "/usr/local/libexec/jdn-gateway"
		}
		object := filepath.Join(libexec, "guard.bpf.o")
		data, err := os.ReadFile(object)
		if err != nil {
			return p, err
		}
		p.Object = &gateway.BootABI{Object: object, SHA256: digest(data)}
		data, err = json.Marshal(p.Object)
		if err != nil {
			return p, err
		}
		path := gateway.BootABIPath(config)
		if err := p.add(path, append(data, '\n'), 0600, false); err != nil {
			return p, err
		}
		if p.Changes[len(p.Changes)-1].Before.Exists {
			return p, fmt.Errorf("an existing rollback ABI record already owns %s", path)
		}
	}
	if err := p.add(legacyGuardPath, wrapper("legacy-guard"), 0755, true); err != nil {
		return p, err
	}
	for _, diagnostic := range []struct{ path, kind string }{
		{"/usr/local/libexec/traceroute-direct", "traceroute"}, {"/usr/local/bin/ping", "ping"},
	} {
		if err := p.add(diagnostic.path, wrapper("diagnostic "+diagnostic.kind+" "+configPath), 0755, diagnostic.kind != "ping"); err != nil {
			return p, err
		}
	}
	if config.NativeTUN {
		if err := p.add(hookPath, wrapper("native hook"), 0755, true); err != nil {
			return p, err
		}
		if err := p.add("/usr/local/sbin/gateway-whitelist", wrapper("whitelist"), 0755, true); err != nil {
			return p, err
		}
	} else if err := p.coreUnit(); err != nil {
		return p, err
	}
	return p, nil
}

func (p *plan) add(path string, data []byte, mode os.FileMode, requireExisting bool) error {
	current, err := readFile(path)
	if err != nil {
		return err
	}
	if requireExisting && !current.Exists {
		return fmt.Errorf("expected legacy installation file %s", path)
	}
	p.Changes = append(p.Changes, change{path, current, fileState{Exists: true, Mode: mode, Data: data}})
	return nil
}

func wrapper(command string) []byte {
	return []byte("#!/bin/sh\nexec " + binaryPath + " " + command + " \"$@\"\n")
}

func digest(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

var captureHook = regexp.MustCompile(`^(ExecStartPre|ExecStopPost)=([+@!:~-]*)/usr/bin/python3[ \t]+(/usr/local/libexec/[^ \t]+)[ \t]+(start|stop)([ \t].*)?$`)

func (p *plan) coreUnit() error {
	data, err := system.Command("", "systemctl", "show", "-p", "FragmentPath", "--value", p.Service)
	if err != nil {
		return err
	}
	path := strings.TrimSpace(string(data))
	if path != filepath.Join("/etc/systemd/system", p.Service) {
		return fmt.Errorf("legacy core service definition is outside /etc/systemd/system")
	}
	state, err := readFile(path)
	if err != nil {
		return err
	}
	kind := "tproxy"
	if p.Config.Proxy.Mode == "tun" {
		kind = "managed-tun"
	}
	hookName := "core-tproxy.py"
	if kind == "managed-tun" {
		hookName = "core-tun.py"
	}
	out := strings.Split(string(state.Data), "\n")
	var start, stop int
	for i, line := range out {
		m := captureHook.FindStringSubmatch(line)
		if m == nil || filepath.Base(m[3]) != hookName && filepath.Base(m[3]) != "jdn-"+hookName {
			continue
		}
		opts := strings.Fields(m[5])
		if len(opts) != 0 && !(len(opts) == 2 && opts[0] == "--config" && opts[1] == configPath) {
			return fmt.Errorf("core interception uses unrecognized arguments in %s", path)
		}
		switch {
		case m[1] == "ExecStartPre" && m[4] == "start":
			out[i] = m[1] + "=" + m[2] + binaryPath + " " + kind + " start " + configPath
			start++
		case m[1] == "ExecStopPost" && m[4] == "stop":
			out[i] = m[1] + "=" + m[2] + binaryPath + " " + kind + " stop"
			stop++
		}
	}
	if start != 1 || stop != 1 {
		return fmt.Errorf("expected one legacy interception start and stop in %s", path)
	}
	p.Changes = append(p.Changes, change{path, state, fileState{Exists: true, Mode: state.Mode, Data: []byte(strings.Join(out, "\n"))}})
	return nil
}

func Plan() (map[string]any, error) {
	p, err := buildPlan()
	if err != nil {
		return nil, err
	}
	paths := []string{binaryPath}
	for _, item := range p.Changes {
		paths = append(paths, item.Path)
	}
	return map[string]any{
		"configuration": configPath, "backend": p.Service, "interface": p.Config.Interface,
		"settings_abi_bytes": p.ABI, "network_sha256": p.PolicySHA, "files": paths,
	}, nil
}
