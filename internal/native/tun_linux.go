//go:build linux

package native

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"

	"golang.org/x/sys/unix"
)

const (
	tunName    = "tun0"
	tunAddress = "10.0.85.2/30"
	tunState   = "/run/jdn-v2raya-tun.json"
)

type Snapshot struct {
	Device  string `json:"device"`
	Ifindex uint32 `json:"ifindex"`
	BootID  string `json:"boot_id"`
	Process
}

type Process struct {
	PID       int    `json:"pid"`
	StartTime string `json:"starttime"`
	NetNS     uint64 `json:"netns"`
}

type nativeSetting struct {
	Type      string `json:"transparentType"`
	PAC       string `json:"pacMode"`
	Auto      bool   `json:"tunAutoRoute"`
	Forward   bool   `json:"ipforward"`
	Setup     string `json:"tunSetupScript"`
	Teardown  string `json:"tunTeardownScript"`
	DNS       string `json:"dnsListenAddr"`
	DNSHijack string `json:"dnsHijack"`
}

func PrepareTUNApproval(config policy.Config, geoIP string, running bool) (policy.Approved, error) {
	if _, err := validateSettings(config.NativeConfDir); err != nil {
		return policy.Approved{}, err
	}
	whitelist, err := ReadWhitelist(config)
	if err != nil {
		return policy.Approved{}, err
	}
	if !running && geoIP == "" {
		geoIP = "/usr/share/v2raya/geoip.dat"
	}
	return Approval(config, whitelist, geoIP)
}

func validateSettings(confdir string) (uint16, error) {
	var setting nativeSetting
	if err := readSetting(confdir, settingsKey, &setting); err != nil {
		return 0, err
	}
	listener, err := netip.ParseAddrPort(setting.DNS)
	if err != nil || !listener.Addr().Is4() || !listener.Addr().IsUnspecified() || listener.Port() == 0 {
		return 0, fmt.Errorf("native guarded TUN requires a wildcard IPv4 DNS listener")
	}
	if setting.Type != "tun" || setting.PAC != "whitelist" || !setting.Auto || !setting.Forward ||
		setting.Setup != "" || setting.Teardown != "" || setting.DNSHijack != "yes" {
		return 0, fmt.Errorf("unsupported native TUN routing or DNS settings")
	}
	data, err := os.ReadFile(filepath.Join(confdir, "config.json"))
	if err != nil {
		return 0, err
	}
	var generated struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			TUN      struct {
				Name     string   `json:"name"`
				Address4 string   `json:"address4"`
				Address6 string   `json:"address6"`
				MTU      int      `json:"mtu"`
				Direct   string   `json:"directTag"`
				DNS      string   `json:"dnsTarget"`
				Excluded []string `json:"excludeProcesses"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &generated); err != nil {
		return 0, fmt.Errorf("invalid generated v2rayA configuration")
	}
	count := 0
	for _, inbound := range generated.Inbounds {
		if inbound.Tag != "transparent" {
			continue
		}
		count++
		tun := inbound.TUN
		if inbound.Protocol != "tun-mips" || tun.Name != tunName || tun.Address4 != tunAddress || tun.MTU != 1500 ||
			tun.Direct != "direct" || tun.Address6 != "" && tun.Address6 != "fdfe:dcba:9876::2/126" ||
			!slices.Contains(tun.Excluded, "v2raya") || !slices.Contains(tun.Excluded, "v2raya_core") ||
			tun.DNS != fmt.Sprintf("127.0.0.1:%d", listener.Port()) {
			return 0, fmt.Errorf("generated native TUN device, bypass or DNS settings differ")
		}
	}
	if count != 1 {
		return 0, fmt.Errorf("expected exactly one native TUN inbound")
	}
	return listener.Port(), nil
}

func proc(pid int) string {
	return filepath.Join("/proc", strconv.Itoa(pid))
}

func process(pid int) (Process, error) {
	base := proc(pid)
	status, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return Process{}, err
	}
	root := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			root = slices.Equal(strings.Fields(line), []string{"Uid:", "0", "0", "0", "0"})
			break
		}
	}
	if !root {
		return Process{}, fmt.Errorf("native proxy must run with root ownership")
	}
	raw, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return Process{}, err
	}
	commEnd := bytes.LastIndexByte(raw, ')')
	if commEnd == -1 {
		return Process{}, fmt.Errorf("invalid native proxy process stat")
	}
	fields := strings.Fields(string(raw[commEnd+1:]))
	if len(fields) < 20 {
		return Process{}, fmt.Errorf("missing native process start time")
	}
	var namespace unix.Stat_t
	if err := unix.Stat(filepath.Join(base, "ns/net"), &namespace); err != nil {
		return Process{}, err
	}
	return Process{PID: pid, StartTime: fields[19], NetNS: namespace.Ino}, nil
}

func manager(config policy.Config) (Process, error) {
	raw, err := system.Command("", "systemctl", "show", config.NativeService, "-p", "MainPID", "--value")
	if err != nil {
		return Process{}, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		return Process{}, fmt.Errorf("v2rayA manager is not running")
	}
	exe, err := os.Readlink(filepath.Join(proc(pid), "exe"))
	if err != nil {
		return Process{}, err
	}
	if filepath.Base(exe) != "v2raya" {
		return Process{}, fmt.Errorf("unexpected v2rayA manager executable")
	}
	return process(pid)
}

func children(pid int) (map[int]struct{}, error) {
	tasks := filepath.Join(proc(pid), "task")
	list, err := os.ReadDir(tasks)
	if err != nil {
		return nil, err
	}
	result := make(map[int]struct{})
	for _, task := range list {
		raw, err := os.ReadFile(filepath.Join(tasks, task.Name(), "children"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, value := range strings.Fields(string(raw)) {
			child, err := strconv.Atoi(value)
			if err != nil || child <= 1 {
				return nil, fmt.Errorf("invalid native proxy child PID")
			}
			result[child] = struct{}{}
		}
	}
	return result, nil
}

func holdsTUN(pid int) (bool, error) {
	base := filepath.Join(proc(pid), "fdinfo")
	entries, err := os.ReadDir(base)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(base, entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if slices.Equal(strings.Fields(line), []string{"iff:", tunName}) {
				return true, nil
			}
		}
	}
	return false, nil
}

func verifiedCore(config policy.Config, parent Process) (Process, error) {
	var current Process
	var localNS unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &localNS); err != nil {
		return current, err
	}
	if parent.NetNS != localNS.Ino {
		return current, fmt.Errorf("native manager resides in another network namespace")
	}
	pids, err := children(parent.PID)
	if err != nil {
		return current, err
	}
	expectedArg := "--config=" + filepath.Join(config.NativeConfDir, "config.json")
	for pid := range pids {
		exe, err := os.Readlink(filepath.Join(proc(pid), "exe"))
		if err != nil {
			return Process{}, err
		}
		if filepath.Base(exe) != "v2raya_core" {
			continue
		}
		core, err := process(pid)
		if err != nil {
			return Process{}, err
		}
		cmd, err := os.ReadFile(filepath.Join(proc(pid), "cmdline"))
		if err != nil {
			return Process{}, err
		}
		if core.NetNS != localNS.Ino || !slices.Contains(strings.Split(string(cmd), "\x00"), expectedArg) {
			return Process{}, fmt.Errorf("native core namespace or configuration path differs")
		}
		holds, err := holdsTUN(pid)
		if err != nil {
			return Process{}, err
		}
		if !holds || current.PID != 0 {
			return Process{}, fmt.Errorf("expected one native core with a TUN descriptor")
		}
		current = core
	}
	if current.PID == 0 {
		return current, fmt.Errorf("expected one verified v2rayA core")
	}
	return current, nil
}

func inspectDevice() (uint32, error) {
	raw, err := system.Command("", "ip", "-j", "-details", "-4", "address", "show", "dev", tunName)
	if err != nil {
		return 0, err
	}
	var links []struct {
		Index uint32 `json:"ifindex"`
		Info  struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
		Addrs []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Bits   int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(raw, &links); err != nil {
		return 0, err
	}
	if len(links) != 1 || links[0].Index == 0 || links[0].Info.Kind != "tun" ||
		len(links[0].Addrs) != 1 || links[0].Addrs[0].Family != "inet" ||
		fmt.Sprintf("%s/%d", links[0].Addrs[0].Local, links[0].Addrs[0].Bits) != tunAddress {
		return 0, fmt.Errorf("native TUN type or IPv4 address differs")
	}
	for _, record := range []struct{ file, value string }{
		{"tun_flags", "0x5001"}, {"owner", "-1"}, {"group", "-1"},
	} {
		raw, err := os.ReadFile(filepath.Join("/sys/class/net", tunName, record.file))
		if err != nil {
			return 0, err
		}
		if strings.TrimSpace(string(raw)) != record.value {
			return 0, fmt.Errorf("native TUN %s differs", record.file)
		}
	}
	return links[0].Index, nil
}

func Inspect(config policy.Config) (Snapshot, error) {
	if !config.NativeTUN {
		return Snapshot{}, fmt.Errorf("native TUN inspection requires native TUN mode")
	}
	if _, err := validateSettings(config.NativeConfDir); err != nil {
		return Snapshot{}, err
	}
	parent, err := manager(config)
	if err != nil {
		return Snapshot{}, err
	}
	core, err := verifiedCore(config, parent)
	if err != nil {
		return Snapshot{}, err
	}
	index, err := inspectDevice()
	if err != nil {
		return Snapshot{}, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return Snapshot{}, err
	}
	if latest, err := process(core.PID); err != nil || latest != core {
		return Snapshot{}, fmt.Errorf("native core changed during inspection")
	}
	if latest, err := manager(config); err != nil || latest != parent {
		return Snapshot{}, fmt.Errorf("native manager changed during inspection")
	}
	return Snapshot{
		Device: tunName, Ifindex: index, BootID: strings.TrimSpace(string(boot)), Process: core,
	}, nil
}

func Identity(config policy.Config) (Snapshot, error) {
	data, err := os.ReadFile(tunState)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	var expected Snapshot
	if err := json.Unmarshal(data, &expected); err != nil {
		return Snapshot{}, err
	}
	actual, err := Inspect(config)
	if err != nil {
		return Snapshot{}, err
	}
	if actual != expected {
		return Snapshot{}, fmt.Errorf("native TUN identity no longer matches its lifecycle snapshot")
	}
	return actual, nil
}

func Publish(snapshot Snapshot) error {
	if snapshot.Ifindex == 0 {
		if err := os.Remove(tunState); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return system.WriteAtomic(tunState, append(raw, '\n'), 0600)
}
