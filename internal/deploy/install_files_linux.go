//go:build linux

package deploy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func (p *installPlan) addNew(path string, data []byte, mode os.FileMode) error {
	state, err := readFile(path)
	if err != nil {
		return err
	}
	if state.Exists {
		return fmt.Errorf("refusing to replace existing local file %s", path)
	}
	p.Changes = append(p.Changes, change{Path: path, Before: state, After: fileState{Exists: true, Mode: mode, Data: data}})
	return nil
}

func (p *installPlan) renderInstall() error {
	config, err := json.Marshal(p.Config)
	if err != nil {
		return err
	}
	gate := binaryPath + " guard ensure " + configPath + " " + p.Config.Interface
	netUnit := strings.ReplaceAll(p.Config.Interface, "-", `\x2d`)
	device := "sys-subsystem-net-devices-" + netUnit + ".device"
	unit := fmt.Sprintf(`[Unit]
Description=Clatch independent nftables and TCX egress guard
DefaultDependencies=no
Requires=%[1]s
After=local-fs.target systemd-sysctl.service systemd-modules-load.service %[1]s
Wants=network-pre.target
Before=network-pre.target networking.service nftables.service %[2]s shutdown.target
Conflicts=shutdown.target
[Service]
Type=oneshot
RemainAfterExit=yes
LimitMEMLOCK=infinity
ExecStart=%[3]s
ExecReload=%[3]s
TimeoutStartSec=90
[Install]
WantedBy=sysinit.target
`, device, p.Service, gate)
	dependencies := "[Unit]\nRequires=" + GuardUnit + "\nAfter=" + GuardUnit + "\n"
	backend := dependencies + "[Service]\nExecStartPre=+" + gate + "\n"
	if p.Config.Proxy != nil {
		kind, port := "tproxy", " "+strconv.Itoa(int(p.Port))
		if p.Config.IsTUN() {
			kind, port = "managed-tun", ""
		}
		backend += "ExecStartPre=+" + binaryPath + " " + kind + " start " + configPath + port + "\n"
		backend += "ExecStopPost=+" + binaryPath + " " + kind + " stop\n"
		if p.Config.Proxy.Kind == "xray-core" {
			backend += "UnsetEnvironment=XRAY_LOCATION_CONFDIR XRAY_LOCATION_CONFIG\n"
		}
	}
	// Preserve the baseline nftables loader and reinstall the Clatch table
	// after it. Attached TCX remains in force during a ruleset replacement.
	nft := dependencies + "[Service]\nExecStartPost=+" + gate + "\nExecReload=\nExecReload=+" + gate + "\nExecStop=\n"
	files := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{configPath, append(config, '\n'), 0600},
		{legacyGuardPath, wrapper("legacy-guard"), 0755},
		{"/usr/local/bin/ping", wrapper("diagnostic ping " + configPath), 0755},
		{"/usr/local/bin/traceroute", wrapper("diagnostic traceroute " + configPath), 0755},
		{defaultSysctl, []byte(strings.Join(p.sysctlKeys(), "=0\n") + "=0\n"), 0644},
		{filepath.Join("/etc/systemd/system", GuardUnit), []byte(unit), 0644},
		{installDropIn("networking.service"), []byte(dependencies), 0644},
		{installDropIn("ifup@" + netUnit + ".service"), []byte(dependencies), 0644},
		{installDropIn("nftables.service"), []byte(nft), 0644},
		{installDropIn(p.Service), []byte(backend), 0644},
	}
	for _, file := range files {
		if err := p.addNew(file.path, file.data, file.mode); err != nil {
			return err
		}
	}
	interfaces, err := readFile(interfacesPath)
	if err != nil {
		return err
	}
	updated, err := gatedInterfaces(string(interfaces.Data), p.Profile, gate)
	if err != nil {
		return err
	}
	p.Changes = append(p.Changes, change{interfacesPath, interfaces, fileState{Exists: true, Mode: interfaces.Mode, Data: []byte(updated)}})
	if p.Config.IsNative() {
		return p.nativeFiles()
	}
	return nil
}

func installDropIn(unit string) string {
	return filepath.Join("/etc/systemd/system", unit+".d", "90-clatch.conf")
}

func (p *installPlan) nativeFiles() error {
	const environment = "/etc/default/v2raya"
	if err := p.addNew(hookPath, wrapper("native hook"), 0755); err != nil {
		return err
	}
	if err := p.addNew("/usr/local/sbin/gateway-whitelist", wrapper("whitelist"), 0755); err != nil {
		return err
	}
	before, err := readFile(environment)
	if err != nil {
		return err
	}
	text := string(before.Data)
	if regexp.MustCompile(`(?m)^\s*(export\s+)?V2RAYA_TRANSPARENT_HOOK\s*=`).MatchString(text) {
		return fmt.Errorf("existing native manager hook requires review at %s", environment)
	}
	mode := before.Mode
	if !before.Exists {
		mode = 0600
	}
	text = strings.TrimRight(text, "\n") + "\nV2RAYA_TRANSPARENT_HOOK=" + hookPath + "\n"
	p.Changes = append(p.Changes, change{environment, before, fileState{Exists: true, Mode: mode, Data: []byte(text)}})
	return nil
}

func (p installPlan) sysctlKeys() []string {
	keys := []string{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", "net.ipv6.conf.default.forwarding"}
	for _, scope := range []string{"all", "default", p.Config.Interface} {
		if p.Config.IsTUN() {
			keys = append(keys, "net.ipv4.conf."+scope+".rp_filter")
		}
		for _, key := range []string{"send_redirects", "accept_redirects", "secure_redirects"} {
			keys = append(keys, "net.ipv4.conf."+scope+"."+key)
		}
		for _, key := range []string{"accept_ra", "accept_redirects"} {
			keys = append(keys, "net.ipv6.conf."+scope+"."+key)
		}
	}
	return keys
}

func gatedInterfaces(text string, profile installProfile, gate string) (string, error) {
	if strings.Contains(text, "gateway-guard") || strings.Contains(text, "clatch guard") {
		return "", fmt.Errorf("existing ifupdown guard requires explicit migration")
	}
	lines := strings.Split(text, "\n")
	start, end := -1, len(lines)
	for i, line := range lines {
		line, _ = strings.CutPrefix(line, "\ufeff")
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "iface" && fields[1] == profile.Interface && fields[2] == "inet" {
			if len(fields) != 4 || fields[3] != "static" || start != -1 {
				return "", fmt.Errorf("expected one matching static ifupdown stanza")
			}
			start = i
		} else if start >= 0 && end == len(lines) && len(fields) != 0 &&
			(fields[0] == "iface" || fields[0] == "mapping" || fields[0] == "auto" ||
				strings.HasPrefix(fields[0], "allow-") || strings.HasPrefix(fields[0], "source")) {
			end = i
		}
	}
	if start == -1 {
		return "", fmt.Errorf("missing static ifupdown stanza for %s", profile.Interface)
	}
	values := make(map[string]string)
	for _, line := range lines[start+1 : end] {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "address" && fields[0] != "netmask" && fields[0] != "gateway" {
			continue
		}
		if len(fields) != 2 || values[fields[0]] != "" {
			return "", fmt.Errorf("ambiguous ifupdown address settings")
		}
		values[fields[0]] = fields[1]
	}
	address := values["address"]
	if !strings.Contains(address, "/") && values["netmask"] != "" {
		bits, err := strconv.Atoi(values["netmask"])
		if err != nil {
			mask := net.ParseIP(values["netmask"]).To4()
			var total int
			bits, total = net.IPMask(mask).Size()
			if total != 32 {
				return "", fmt.Errorf("invalid ifupdown IPv4 netmask")
			}
		}
		address += "/" + strconv.Itoa(bits)
	}
	prefix, err := netip.ParsePrefix(address)
	if err != nil || prefix.String() != profile.Address || values["gateway"] != profile.Gateway {
		return "", fmt.Errorf("ifupdown address or default gateway differs from the profile")
	}
	lines[start] += "\n    pre-up " + gate
	return strings.Join(lines, "\n"), nil
}
