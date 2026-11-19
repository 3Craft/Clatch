//go:build linux

package deploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"clatch-gateway/internal/firewall"
	"clatch-gateway/internal/gateway"
	"clatch-gateway/internal/native"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/proxy"
	"clatch-gateway/internal/system"
)

const (
	GuardUnit      = "clatch-guard.service"
	configPath     = policy.DefaultConfigPath
	installState   = policy.DefaultConfigDir + "/clatch-install.json"
	interfacesPath = "/etc/network/interfaces"
	defaultPolicy  = policy.DefaultConfigDir + "/approved-policy.json"
	defaultSource  = policy.DefaultConfigDir + "/source-policy.json"
	defaultRules   = policy.DefaultConfigDir + "/guard.nft"
	defaultPins    = "/sys/fs/bpf/jdn_gateway"
	defaultSysctl  = "/etc/sysctl.d/99-zzzz-clatch-guard.conf"
)

type installProfile struct {
	Schema      int                `json:"schema"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Interface   string             `json:"interface"`
	Address     string             `json:"address"`
	Gateway     string             `json:"gateway"`
	LAN         []string           `json:"lan"`
	PublicIPv6  bool               `json:"public_ipv6"`
	Proxy       *policy.Proxy      `json:"proxy"`
	NativeMode  string             `json:"native_mode"`
	GeoIP       string             `json:"geoip"`
	Diagnostic  *policy.Diagnostic `json:"lan_icmp_diagnostic"`
}

type installPlan struct {
	plan
	Profile     installProfile
	Approval    policy.Approved
	Port        uint16
	NewAccount  bool
	ProxyActive bool
	NFTActive   bool
	NFTEnabled  string
}

var installInterface = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,14}$`)

func readInstallProfile(path string) (installProfile, error) {
	var profile installProfile
	raw, err := os.ReadFile(path)
	if err != nil {
		return profile, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return profile, err
	}
	if decoder.Decode(new(any)) != io.EOF || profile.Schema != 1 || profile.PublicIPv6 ||
		!installInterface.MatchString(profile.Interface) || profile.Interface == "lo" {
		return profile, fmt.Errorf("expected a schema-1 single-interface IPv4 profile")
	}
	address, err := netip.ParsePrefix(profile.Address)
	upstream, gatewayErr := netip.ParseAddr(profile.Gateway)
	if err != nil || gatewayErr != nil || !address.Addr().Is4() || !upstream.Is4() ||
		!address.Addr().IsGlobalUnicast() || !upstream.IsGlobalUnicast() ||
		address.Bits() == 0 || address.Addr() == upstream || !address.Contains(upstream) ||
		!usableSubnetHost(address.Masked(), address.Addr()) || !usableSubnetHost(address.Masked(), upstream) {
		return profile, fmt.Errorf("static address and upstream must be distinct IPv4 hosts on the connected subnet")
	}
	for _, entry := range profile.LAN {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 || prefix.Masked() != prefix {
			return profile, fmt.Errorf("LAN requires explicit canonical IPv4 prefixes")
		}
	}
	return profile, nil
}

func usableSubnetHost(prefix netip.Prefix, address netip.Addr) bool {
	if prefix.Bits() >= 31 {
		return true
	}
	return prefix.Contains(address) && address != prefix.Addr() && prefix.Contains(address.Next())
}

func makeInstallPlan(path string, test bool) (installPlan, error) {
	var p installPlan
	if err := verifyDebian13(); err != nil {
		return p, err
	}
	var err error
	p.Profile, err = readInstallProfile(path)
	if err != nil {
		return p, err
	}
	for _, item := range []string{configPath, legacyConfigPath, legacyGuardPath, binaryPath, defaultPolicy, defaultRules,
		defaultSource, defaultPins, defaultSysctl, filepath.Join("/etc/systemd/system", GuardUnit),
		filepath.Join("/etc/systemd/system", legacyGuardUnit), installState, retainedSysctl, nativePinsRecord} {
		if _, err := os.Lstat(item); !errors.Is(err, os.ErrNotExist) {
			return p, fmt.Errorf("an existing or inaccessible gateway artifact requires review at %s", item)
		}
	}
	for _, command := range []string{"systemctl", "systemd-analyze", "ip", "tc", "nft", "sysctl", "ifup", "useradd"} {
		if _, err := exec.LookPath(command); err != nil {
			return p, err
		}
	}
	for _, path := range []string{"/usr/bin/ping", "/usr/bin/traceroute.db"} {
		if _, err := os.Stat(path); err != nil {
			return p, err
		}
	}
	uid, create, err := installDiagnosticUID()
	if err != nil {
		return p, err
	}
	address := netip.MustParsePrefix(p.Profile.Address)
	p.NewAccount = create
	p.Config = policy.Config{Interface: p.Profile.Interface, DiagnosticUID: uid,
		Pins: defaultPins, ApprovedPolicy: defaultPolicy, RulesFile: defaultRules, LAN: p.Profile.LAN,
		Local: []string{address.Addr().String() + "/32"}, Proxy: p.Profile.Proxy, Diagnostic: p.Profile.Diagnostic}
	if p.Config.IsNative() {
		mode, err := native.Mode("/etc/v2raya")
		if err != nil {
			return p, err
		}
		if p.Profile.NativeMode != "" && p.Profile.NativeMode != mode {
			return p, fmt.Errorf("native mode differs from the v2rayA database")
		}
		p.Config.NativeTUN = mode == "tun"
	} else if p.Profile.NativeMode != "" {
		return p, fmt.Errorf("native_mode is only available for a v2rayA profile")
	}
	if err := p.Config.Validate(); err != nil {
		return p, err
	}
	p.Service = "v2raya.service"
	if p.Config.Proxy != nil {
		p.Service = p.Config.Proxy.Service
		if filepath.Base(p.Service) != p.Service || !strings.HasSuffix(p.Service, ".service") {
			return p, fmt.Errorf("proxy service must name an installed .service unit")
		}
	}
	p.ProxyActive, err = unitActive(p.Service)
	if err != nil {
		return p, err
	}
	p.NFTActive, err = unitActive("nftables.service")
	if err != nil {
		return p, err
	}
	p.NFTEnabled, err = unitProperty("nftables.service", "UnitFileState")
	if err != nil {
		return p, err
	}
	if p.NFTEnabled != "enabled" && p.NFTEnabled != "disabled" && p.NFTEnabled != "enabled-runtime" {
		return p, fmt.Errorf("unsupported existing nftables unit enablement %q", p.NFTEnabled)
	}
	if err := verifyInstallNetwork(p.Config, address, p.Profile.Gateway); err != nil {
		return p, err
	}
	if err := firewall.RequireUnusedGuardTable(); err != nil {
		return p, err
	}
	if p.Config.IsNative() {
		p.Approval, err = native.PrepareApproval(p.Config, p.Profile.GeoIP, p.ProxyActive)
	} else {
		if p.Profile.GeoIP != "" {
			return p, fmt.Errorf("standalone profiles use a CIDR policy file")
		}
		if p.Port, err = proxy.Preflight(p.Config, test); err != nil {
			return p, err
		}
		var source policy.Source
		source, err = policy.ReadSource(p.Config.Proxy.PolicySource)
		if err == nil {
			p.Approval, err = p.Config.ApprovalFor(source)
		}
		if err == nil {
			backend := *p.Config.Proxy
			backend.PolicySource = defaultSource
			p.Config.Proxy = &backend
			err = p.addNew(defaultSource, append(p.Approval.SourcePolicy, '\n'), 0600)
		}
	}
	if err != nil {
		return p, err
	}
	p.PolicySHA = p.Approval.NetworkSHA256
	return p, p.renderInstall()
}

func verifyDebian13() error {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}
	values := make(map[string]string)
	for line := range strings.SplitSeq(string(raw), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = strings.Trim(value, `"'`)
		}
	}
	if values["ID"] != "debian" || values["VERSION_ID"] != "13" {
		return fmt.Errorf("gateway installation requires Debian 13")
	}
	return nil
}

func installDiagnosticUID() (uint32, bool, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/overflowuid")
	if err != nil {
		return 0, false, err
	}
	overflow, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		return 0, false, err
	}
	account, err := user.Lookup("jdn-trace")
	if err == nil {
		group, groupErr := user.LookupGroup("jdn-trace")
		uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
		if groupErr != nil || uidErr != nil || group.Gid != account.Gid || uid == 0 || uid == overflow || uid == 65534 || uid == 0xffffffff {
			return 0, false, fmt.Errorf("existing jdn-trace account must be an unprivileged system identity")
		}
		if err := requireDedicatedDiagnosticUID(account.Uid); err != nil {
			return 0, false, err
		}
		return uint32(uid), false, nil
	}
	var missing user.UnknownUserError
	if !errors.As(err, &missing) {
		return 0, false, err
	}
	_, groupErr := user.LookupGroup("jdn-trace")
	var unknownGroup user.UnknownGroupError
	if !errors.As(groupErr, &unknownGroup) {
		return 0, false, fmt.Errorf("jdn-trace group already exists or cannot be verified")
	}
	for uid := 999; uid >= 200; uid-- {
		if uint64(uid) == overflow {
			continue
		}
		_, err := user.LookupId(strconv.Itoa(uid))
		var absent user.UnknownUserIdError
		if errors.As(err, &absent) {
			return uint32(uid), true, nil
		}
		if err != nil {
			return 0, false, err
		}
	}
	return 0, false, fmt.Errorf("no available system UID for jdn-trace")
}

func requireDedicatedDiagnosticUID(uid string) error {
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return err
	}
	found := false
	for line := range strings.SplitSeq(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[2] != uid {
			continue
		}
		if found || fields[0] != "jdn-trace" || fields[6] != "/usr/sbin/nologin" && fields[6] != "/sbin/nologin" && fields[6] != "/bin/false" {
			return fmt.Errorf("jdn-trace must use a dedicated non-login UID")
		}
		found = true
	}
	if !found {
		return fmt.Errorf("jdn-trace UID is absent from the local account database")
	}
	return nil
}

func unitProperty(unit, property string) (string, error) {
	raw, err := system.Command("", "systemctl", "show", "--property="+property, "--value", unit)
	return strings.TrimSpace(string(raw)), err
}

func unitActive(unit string) (bool, error) {
	state, err := unitProperty(unit, "ActiveState")
	if err != nil {
		return false, err
	}
	switch state {
	case "active":
		return true, nil
	case "inactive", "failed":
		return false, nil
	default:
		return false, fmt.Errorf("unit %s is currently %s", unit, state)
	}
}

func verifyInstallNetwork(config policy.Config, address netip.Prefix, upstream string) error {
	iface, err := net.InterfaceByName(config.Interface)
	if err != nil || len(iface.HardwareAddr) != 6 || iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("the configured Ethernet interface must already be up")
	}
	if _, err := os.Lstat(filepath.Join("/sys/class/net", iface.Name, "master")); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("guard interface must be a standalone Ethernet device")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	found := false
	for _, link := range interfaces {
		if link.Flags&net.FlagLoopback != 0 || link.Name == config.TUNDevice() {
			continue
		}
		addresses, err := link.Addrs()
		if err != nil {
			return err
		}
		for _, raw := range addresses {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil {
				return err
			}
			if prefix.Addr().IsLinkLocalUnicast() {
				continue
			}
			if link.Name != iface.Name || prefix != address {
				return fmt.Errorf("unreviewed IP address on %s", link.Name)
			}
			found = true
		}
	}
	if !found {
		return fmt.Errorf("live IPv4 address differs from the static profile")
	}
	var routes []struct {
		Gateway string `json:"gateway"`
		Device  string `json:"dev"`
	}
	raw, err := system.Command("", "ip", "-j", "-4", "route", "show", "default")
	if err != nil || json.Unmarshal(raw, &routes) != nil || len(routes) != 1 || routes[0].Device != iface.Name || routes[0].Gateway != upstream {
		return fmt.Errorf("expected a single IPv4 default route matching the static profile")
	}
	return gateway.CheckUnusedEgress(iface.Name)
}
