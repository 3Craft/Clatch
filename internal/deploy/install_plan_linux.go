//go:build linux

package deploy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
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
	defaultPins    = "/sys/fs/bpf/clatch"
	defaultSysctl  = "/etc/sysctl.d/99-zzzz-clatch-guard.conf"
	traceAccount   = "clatch-trace"
)

type installPlan struct {
	plan
	Profile      InstallProfile
	Approval     policy.Approved
	Port         uint16
	NewAccount   bool
	ProxyActive  bool
	NFTActive    bool
	NFTEnabled   string
	NetworkStack string // "ifupdown" or "systemd-networkd"
}

func makeInstallPlan(path string, test bool) (installPlan, error) {
	var p installPlan
	if err := verifySupportedHost(); err != nil {
		return p, err
	}
	var err error
	p.Profile, err = ReadInstallProfile(path)
	if err != nil {
		return p, err
	}
	for _, item := range []string{configPath, binaryPath, defaultPolicy, defaultRules,
		defaultSource, defaultPins, defaultSysctl, filepath.Join("/etc/systemd/system", GuardUnit),
		installState, retainedSysctl, nativePinsRecord} {
		if _, err := os.Lstat(item); !errors.Is(err, os.ErrNotExist) {
			return p, fmt.Errorf("an existing or inaccessible gateway artifact requires review at %s (use `clatch upgrade` or `clatch uninstall`)", item)
		}
	}
	for _, command := range []string{"systemctl", "systemd-analyze", "ip", "tc", "nft", "sysctl", "useradd"} {
		if _, err := exec.LookPath(command); err != nil {
			return p, err
		}
	}
	if _, err := os.Stat("/usr/bin/ping"); err != nil {
		return p, err
	}
	if _, err := os.Stat("/usr/bin/traceroute.db"); err != nil {
		if _, err2 := os.Stat("/usr/bin/traceroute"); err2 != nil {
			return p, fmt.Errorf("traceroute binary not found at /usr/bin/traceroute.db or /usr/bin/traceroute")
		}
	}
	p.NetworkStack, err = detectNetworkStack(p.Profile)
	if err != nil {
		return p, err
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
	if p.NFTEnabled != "" && p.NFTEnabled != "enabled" && p.NFTEnabled != "disabled" && p.NFTEnabled != "enabled-runtime" {
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

func verifySupportedHost() error {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return fmt.Errorf("gateway installation requires a systemd host")
	}
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return err
	}
	rel := strings.TrimSpace(string(raw))
	parts := strings.SplitN(rel, ".", 3)
	if len(parts) < 2 {
		return fmt.Errorf("unrecognized Linux kernel version %q", rel)
	}
	maj, err1 := strconv.Atoi(parts[0])
	minStr := parts[1]
	for i, r := range minStr {
		if r < '0' || r > '9' {
			minStr = minStr[:i]
			break
		}
	}
	min, err2 := strconv.Atoi(minStr)
	if err1 != nil || err2 != nil || maj < 6 || (maj == 6 && min < 6) {
		return fmt.Errorf("gateway installation requires Linux kernel 6.6 or newer for pinned TCX (found %s)", rel)
	}
	return nil
}

func detectNetworkStack(profile InstallProfile) (string, error) {
	if raw, err := os.ReadFile(interfacesPath); err == nil {
		if _, err := exec.LookPath("ifup"); err == nil {
			if _, parseErr := gatedInterfaces(string(raw), profile, binaryPath+" guard ensure "+configPath+" "+profile.Interface); parseErr == nil {
				return "ifupdown", nil
			}
		}
	}
	if active, err := unitActive("systemd-networkd.service"); err == nil && active {
		return "systemd-networkd", nil
	}
	if state, err := unitProperty("systemd-networkd.service", "UnitFileState"); err == nil &&
		(state == "enabled" || state == "enabled-runtime" || state == "static") {
		return "systemd-networkd", nil
	}
	return "", fmt.Errorf("supported network manager not detected: configure a matching static stanza in %s (ifupdown) or use systemd-networkd", interfacesPath)
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
	account, err := user.Lookup(traceAccount)
	if err == nil {
		group, groupErr := user.LookupGroup(traceAccount)
		uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
		if groupErr != nil || uidErr != nil || group.Gid != account.Gid || uid == 0 || uid == overflow || uid == 65534 || uid == 0xffffffff {
			return 0, false, fmt.Errorf("existing %s account must be an unprivileged system identity", traceAccount)
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
	_, groupErr := user.LookupGroup(traceAccount)
	var unknownGroup user.UnknownGroupError
	if !errors.As(groupErr, &unknownGroup) {
		return 0, false, fmt.Errorf("%s group already exists or cannot be verified", traceAccount)
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
	return 0, false, fmt.Errorf("no available system UID for %s", traceAccount)
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
		if found || fields[0] != traceAccount || fields[6] != "/usr/sbin/nologin" && fields[6] != "/sbin/nologin" && fields[6] != "/bin/false" {
			return fmt.Errorf("%s must use a dedicated non-login UID", traceAccount)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("%s UID is absent from the local account database", traceAccount)
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
	case "inactive", "failed", "":
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
	raw, err := system.Command("", "ip", "-j", "-4", "route", "show", "default")
	if err != nil || len(raw) == 0 {
		return fmt.Errorf("expected a single IPv4 default route matching the static profile")
	}
	if err := parseDefaultRoute(raw, iface.Name, upstream); err != nil {
		return err
	}
	return gateway.CheckUnusedEgress(iface.Name)
}
