//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"clatch-gateway/internal/deploy"
	"clatch-gateway/internal/diagnostic"
	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

func tryRunDiagnostic(args []string, stderr io.Writer) (int, bool) {
	if len(args) >= 3 && args[0] == "diagnostic" &&
		(args[1] == "ping" || args[1] == "traceroute") && args[2] != "--help" && args[2] != "-h" {
		code, err := diagnostic.Run(args[1], args[2], args[3:])
		if err != nil {
			fmt.Fprintf(stderr, "clatch: %v\n", err)
		}
		return code, true
	}
	return 0, false
}

func runPlatformCommand(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errUsage
	}
	switch args[0] {
	case "status":
		return runStatus(args[1:])
	case "health":
		return runHealth(args[1:])
	case "stats":
		return runStats(args[1:])
	case "guard":
		return runGuard(args[1:])
	case "install":
		return runInstall(args[1:])
	case "upgrade":
		return runUpgrade(args[1:])
	case "uninstall":
		return runUninstall(args[1:])
	case "whitelist":
		return runWhitelist(args[1:])
	case "policy":
		return runPolicy(args[1:])
	case "openwrt":
		return runOpenWrt(args[1:])
	case "bpf":
		return runBPF(args[1:])
	case "tproxy":
		return runCapture(args[1:])
	case "managed-tun":
		return runManagedTUN(args[1:])
	case "native":
		return runNative(args[1:])
	default:
		return nil, errUsage
	}
}

func runUpgrade(args []string) (any, error) {
	var options inspectionOptions
	var backupDir string
	flags := options.flags("upgrade")
	flags.StringVar(&backupDir, "backup", "", "backup directory for previous binary")
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if err := options.resolve(flags, ""); err != nil {
		return nil, err
	}
	result, err := deploy.Upgrade(options.config, backupDir)
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	if result.Unchanged {
		fmt.Fprintf(&out, "Clatch binary is already up to date\nBinary         %s\nSHA-256        %s\n",
			result.BinaryPath, result.NewSHA256[:12])
	} else {
		fmt.Fprintf(&out, "Clatch upgraded and verified\nBinary         %s\nBackup         %s\nOld SHA-256    %s\nNew SHA-256    %s\n",
			result.BinaryPath, result.BackupPath, result.OldSHA256[:12], result.NewSHA256[:12])
	}
	res := inspection{value: result}
	if !options.json {
		res.text = out.String()
	}
	return res, nil
}

func runUninstall(args []string) (any, error) {
	var options inspectionOptions
	var keepConfig, yes bool
	flags := options.flags("uninstall")
	flags.BoolVar(&keepConfig, "keep-config", false, "keep /etc/clatch configuration and policy files")
	flags.BoolVar(&yes, "yes", false, "execute removal (omit for dry-run preview)")
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if err := options.resolve(flags, ""); err != nil {
		return nil, err
	}
	result, err := deploy.Uninstall(deploy.UninstallOptions{
		ConfigPath: options.config,
		KeepConfig: keepConfig,
		Apply:      yes,
	})
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	if result.Applied {
		fmt.Fprintln(&out, "Clatch uninstalled")
	} else {
		fmt.Fprintln(&out, "Clatch uninstall preview (dry run)")
	}
	fmt.Fprintf(&out, "Configuration  %s (keep_config=%t)\n", result.ConfigPath, result.KeepConfig)
	for _, act := range result.Actions {
		fmt.Fprintf(&out, "  - %s\n", act)
	}
	for _, warn := range result.Warnings {
		fmt.Fprintf(&out, "Warning        %s\n", warn)
	}
	if !result.Applied && len(result.Actions) > 0 {
		fmt.Fprintln(&out, "\nRe-run with --yes to execute removal.")
	}
	res := inspection{value: result}
	if !options.json {
		res.text = out.String()
	}
	return res, nil
}

func detectHostNetwork() (ifaceName, hostCIDR, gateway, lanCIDR string) {
	raw, err := system.Command("", "ip", "-j", "-4", "route", "show", "default")
	if err != nil {
		return "", "", "", ""
	}
	var routes []struct {
		Gateway string `json:"gateway"`
		Device  string `json:"dev"`
	}
	if json.Unmarshal(raw, &routes) != nil || len(routes) == 0 {
		return "", "", "", ""
	}
	ifaceName = routes[0].Device
	gateway = routes[0].Gateway
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return ifaceName, "", gateway, ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ifaceName, "", gateway, ""
	}
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err == nil && p.Addr().Is4() && p.Addr().IsGlobalUnicast() {
			hostCIDR = p.String()
			lanCIDR = p.Masked().String()
			break
		}
	}
	return ifaceName, hostCIDR, gateway, lanCIDR
}

func explainLiveKernel(addr netip.Addr, pins string) (policy.Verdict, error) {
	active, err := guard.Dump(pins)
	if err != nil {
		return policy.Verdict{}, err
	}
	liveEntries := make(guard.Policy, len(active.Entries))
	for _, row := range active.Entries {
		p, pErr := netip.ParsePrefix(row[1].(string))
		if pErr != nil {
			continue
		}
		key := guard.Key{Family: row[0].(uint32), PrefixLen: uint32(p.Bits() + 32)}
		copy(key.Address[:], p.Addr().AsSlice())
		liveEntries[key] = row[2].(uint32)
	}
	return policy.Explain(addr, liveEntries), nil
}

func checkDoctorProfile(path string) []doctorCheck {
	raw := deploy.CheckInstallProfile(path)
	out := make([]doctorCheck, 0, len(raw))
	for _, c := range raw {
		out = append(out, doctorCheck{ID: c.ID, Status: c.Status, Message: c.Message, Hint: c.Hint})
	}
	return out
}

func runHostDoctorChecks(report *doctorReport, profilePath string) {
	osID, osVersion, osPretty := readOSRelease("/etc/os-release")
	if osPretty != "" {
		report.add(doctorCheck{ID: "os.release", Status: "pass", Message: fmt.Sprintf("Detected %s (ID=%s, VERSION_ID=%s)", osPretty, osID, osVersion)})
	} else {
		report.add(doctorCheck{ID: "os.release", Status: "warn", Message: "Could not read /etc/os-release"})
	}

	if release, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		rel := strings.TrimSpace(string(release))
		major, minor, ok := parseKernelVersion(rel)
		if ok && (major > 6 || (major == 6 && minor >= 6)) {
			report.add(doctorCheck{ID: "kernel.tcx", Status: "pass", Message: fmt.Sprintf("Linux kernel %s supports pinned TCX (>= 6.6)", rel)})
		} else if ok {
			report.add(doctorCheck{
				ID:      "kernel.tcx",
				Status:  "fail",
				Message: fmt.Sprintf("Linux kernel %s is older than 6.6", rel),
				Hint:    "Upgrade to Linux 6.6 or newer with BPF TCX support enabled.",
			})
		} else {
			report.add(doctorCheck{ID: "kernel.tcx", Status: "warn", Message: fmt.Sprintf("Unrecognized kernel release %q", rel)})
		}
	} else {
		report.add(doctorCheck{ID: "kernel.tcx", Status: "warn", Message: fmt.Sprintf("Unable to read kernel release: %v", err)})
	}

	if os.Geteuid() == 0 {
		report.add(doctorCheck{ID: "privileges.root", Status: "pass", Message: "Running as root"})
	} else {
		report.add(doctorCheck{
			ID:      "privileges.root",
			Status:  "warn",
			Message: fmt.Sprintf("Running as non-root UID %d", os.Geteuid()),
			Hint:    "Read-only schema/config/explain checks work without root; guard, stats, install, and whitelist require root.",
		})
	}

	if isBPFFSMounted("/proc/mounts") {
		report.add(doctorCheck{ID: "kernel.bpffs", Status: "pass", Message: "bpffs is mounted at /sys/fs/bpf"})
	} else {
		report.add(doctorCheck{
			ID:      "kernel.bpffs",
			Status:  "warn",
			Message: "bpffs is not currently mounted at /sys/fs/bpf",
			Hint:    "Clatch mounts /sys/fs/bpf automatically as root, or mount it manually: `mount -t bpf bpf /sys/fs/bpf`.",
		})
	}

	var missingCore []string
	for _, tool := range []string{"nft", "ip", "tc", "sysctl"} {
		if _, err := exec.LookPath(tool); err != nil {
			missingCore = append(missingCore, tool)
		}
	}
	if len(missingCore) == 0 {
		report.add(doctorCheck{ID: "tools.core", Status: "pass", Message: "Core networking tools available (nft, ip, tc, sysctl)"})
	} else {
		report.add(doctorCheck{
			ID:      "tools.core",
			Status:  "fail",
			Message: fmt.Sprintf("Missing required networking tools: %s", strings.Join(missingCore, ", ")),
			Hint:    "Install nftables, iproute2, and procps before enabling Clatch.",
		})
	}

	if osID != "openwrt" {
		var missingSys []string
		for _, tool := range []string{"systemctl", "systemd-analyze", "useradd"} {
			if _, err := exec.LookPath(tool); err != nil {
				missingSys = append(missingSys, tool)
			}
		}
		if len(missingSys) == 0 {
			report.add(doctorCheck{ID: "tools.systemd", Status: "pass", Message: "System management tools available (systemctl, systemd-analyze, useradd)"})
		} else {
			status := "warn"
			if profilePath != "" {
				status = "fail"
			}
			report.add(doctorCheck{
				ID:      "tools.systemd",
				Status:  status,
				Message: fmt.Sprintf("Missing host install tools: %s", strings.Join(missingSys, ", ")),
				Hint:    "Install systemd utilities before deploying with `clatch install`.",
			})
		}

		hasPing := fileExists("/usr/bin/ping")
		hasTrace := fileExists("/usr/bin/traceroute.db") || fileExists("/usr/bin/traceroute")
		if hasPing && hasTrace {
			report.add(doctorCheck{ID: "tools.diagnostic", Status: "pass", Message: "Diagnostic utilities present (ping and traceroute)"})
		} else {
			status := "warn"
			if profilePath != "" {
				status = "fail"
			}
			report.add(doctorCheck{
				ID:      "tools.diagnostic",
				Status:  status,
				Message: "Missing diagnostic utilities (/usr/bin/ping or traceroute)",
				Hint:    "Install iputils-ping and traceroute packages (`apt install iputils-ping traceroute`).",
			})
		}

		if _, err := exec.LookPath("conntrack"); err == nil {
			report.add(doctorCheck{ID: "tools.conntrack", Status: "pass", Message: "conntrack utility available for `clatch health --conntrack`"})
		} else {
			report.add(doctorCheck{
				ID:      "tools.conntrack",
				Status:  "warn",
				Message: "conntrack utility not found (optional)",
				Hint:    "Install `conntrack` if you plan to run `clatch health --conntrack`.",
			})
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readOSRelease(path string) (id, versionID, pretty string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", ""
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.Trim(val, `"'`)
		switch key {
		case "ID":
			id = val
		case "VERSION_ID":
			versionID = val
		case "PRETTY_NAME":
			pretty = val
		}
	}
	if pretty == "" && id != "" {
		pretty = id
		if versionID != "" {
			pretty += " " + versionID
		}
	}
	return id, versionID, pretty
}

func parseKernelVersion(release string) (major, minor int, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(release), ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
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
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return maj, min, true
}

func isBPFFSMounted(mountsPath string) bool {
	raw, err := os.ReadFile(mountsPath)
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "/sys/fs/bpf" && fields[2] == "bpf" {
			return true
		}
	}
	return false
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
