//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"clatch-gateway/internal/deploy"
	"clatch-gateway/internal/openwrt"
)

type doctorCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // pass, warn, fail
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

type doctorSummary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

type doctorReport struct {
	Passed    bool          `json:"passed"`
	Summary   doctorSummary `json:"summary"`
	Checks    []doctorCheck `json:"checks"`
	NextSteps []string      `json:"next_steps,omitempty"`
}

func runDoctor(args []string) (any, error) {
	var options inspectionOptions
	var profilePath, openwrtPath string
	flags := options.flags("doctor")
	flags.StringVar(&profilePath, "profile", "", "Debian install profile JSON to validate")
	flags.StringVar(&openwrtPath, "openwrt", "", "OpenWrt configuration JSON to validate")
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if err := options.resolve(flags, ""); err != nil {
		return nil, err
	}
	report := runDoctorChecks(options.config, options.explicit, profilePath, openwrtPath)
	var err error
	if !report.Passed {
		err = fmt.Errorf("doctor found %d failing check(s)", report.Summary.Fail)
	}
	res := inspection{value: report}
	if !options.json {
		res.text = report.text()
	}
	return res, err
}

func runDoctorChecks(configPath string, configExplicit bool, profilePath, openwrtPath string) doctorReport {
	var report doctorReport
	add := func(c doctorCheck) {
		report.Checks = append(report.Checks, c)
		switch c.Status {
		case "pass":
			report.Summary.Pass++
		case "warn":
			report.Summary.Warn++
		case "fail":
			report.Summary.Fail++
		}
	}

	// 1. OS release check
	osID, osVersion, osPretty := readOSRelease("/etc/os-release")
	switch {
	case osID == "debian" && osVersion == "13":
		add(doctorCheck{ID: "os.release", Status: "pass", Message: fmt.Sprintf("Detected %s (supported Debian 13 target)", osPretty)})
	case osID == "openwrt":
		add(doctorCheck{ID: "os.release", Status: "pass", Message: fmt.Sprintf("Detected %s (OpenWrt target)", osPretty)})
	case osPretty != "":
		status := "warn"
		if profilePath != "" {
			status = "fail"
		}
		add(doctorCheck{
			ID:      "os.release",
			Status:  status,
			Message: fmt.Sprintf("Detected %s (ID=%s, VERSION_ID=%s)", osPretty, osID, osVersion),
			Hint:    "Automated `clatch install` targets Debian 13 with ifupdown; OpenWrt uses `clatch openwrt`.",
		})
	default:
		add(doctorCheck{ID: "os.release", Status: "warn", Message: "Could not read /etc/os-release"})
	}

	// 2. Kernel version check (>= 6.6 for pinned TCX)
	if release, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		rel := strings.TrimSpace(string(release))
		major, minor, ok := parseKernelVersion(rel)
		if ok && (major > 6 || (major == 6 && minor >= 6)) {
			add(doctorCheck{ID: "kernel.tcx", Status: "pass", Message: fmt.Sprintf("Linux kernel %s supports pinned TCX (>= 6.6)", rel)})
		} else if ok {
			add(doctorCheck{
				ID:      "kernel.tcx",
				Status:  "fail",
				Message: fmt.Sprintf("Linux kernel %s is older than 6.6", rel),
				Hint:    "Upgrade to Linux 6.6 or newer with BPF TCX support enabled.",
			})
		} else {
			add(doctorCheck{ID: "kernel.tcx", Status: "warn", Message: fmt.Sprintf("Unrecognized kernel release %q", rel)})
		}
	} else {
		add(doctorCheck{ID: "kernel.tcx", Status: "warn", Message: fmt.Sprintf("Unable to read kernel release: %v", err)})
	}

	// 3. Privileges
	if os.Geteuid() == 0 {
		add(doctorCheck{ID: "privileges.root", Status: "pass", Message: "Running as root"})
	} else {
		add(doctorCheck{
			ID:      "privileges.root",
			Status:  "warn",
			Message: fmt.Sprintf("Running as non-root UID %d", os.Geteuid()),
			Hint:    "Read-only schema/config/explain checks work without root; guard, stats, install, and whitelist require root.",
		})
	}

	// 4. bpffs mount
	if isBPFFSMounted("/proc/mounts") {
		add(doctorCheck{ID: "kernel.bpffs", Status: "pass", Message: "bpffs is mounted at /sys/fs/bpf"})
	} else {
		add(doctorCheck{
			ID:      "kernel.bpffs",
			Status:  "warn",
			Message: "bpffs is not currently mounted at /sys/fs/bpf",
			Hint:    "Clatch mounts /sys/fs/bpf automatically as root, or mount it manually: `mount -t bpf bpf /sys/fs/bpf`.",
		})
	}

	// 5. Required host commands
	coreTools := []string{"nft", "ip", "tc", "sysctl"}
	var missingCore []string
	for _, tool := range coreTools {
		if _, err := exec.LookPath(tool); err != nil {
			missingCore = append(missingCore, tool)
		}
	}
	if len(missingCore) == 0 {
		add(doctorCheck{ID: "tools.core", Status: "pass", Message: "Core networking tools available (nft, ip, tc, sysctl)"})
	} else {
		add(doctorCheck{
			ID:      "tools.core",
			Status:  "fail",
			Message: fmt.Sprintf("Missing required networking tools: %s", strings.Join(missingCore, ", ")),
			Hint:    "Install nftables, iproute2, and procps before enabling Clatch.",
		})
	}

	if osID != "openwrt" {
		debianTools := []string{"systemctl", "systemd-analyze", "ifup", "useradd"}
		var missingDebian []string
		for _, tool := range debianTools {
			if _, err := exec.LookPath(tool); err != nil {
				missingDebian = append(missingDebian, tool)
			}
		}
		if len(missingDebian) == 0 {
			add(doctorCheck{ID: "tools.debian", Status: "pass", Message: "Debian service and network tools available (systemctl, systemd-analyze, ifup, useradd)"})
		} else {
			status := "warn"
			if profilePath != "" {
				status = "fail"
			}
			add(doctorCheck{
				ID:      "tools.debian",
				Status:  status,
				Message: fmt.Sprintf("Missing Debian install tools: %s", strings.Join(missingDebian, ", ")),
				Hint:    "Install systemd and ifupdown if deploying with `clatch install`.",
			})
		}

		var missingDiag []string
		for _, p := range []string{"/usr/bin/ping", "/usr/bin/traceroute.db"} {
			if _, err := os.Stat(p); err != nil {
				missingDiag = append(missingDiag, p)
			}
		}
		if len(missingDiag) == 0 {
			add(doctorCheck{ID: "tools.diagnostic", Status: "pass", Message: "Diagnostic utilities present (/usr/bin/ping, /usr/bin/traceroute.db)"})
		} else {
			status := "warn"
			if profilePath != "" {
				status = "fail"
			}
			add(doctorCheck{
				ID:      "tools.diagnostic",
				Status:  status,
				Message: fmt.Sprintf("Missing diagnostic binaries: %s", strings.Join(missingDiag, ", ")),
				Hint:    "Install iputils-ping and traceroute packages on Debian (`apt install iputils-ping traceroute`).",
			})
		}

		if _, err := exec.LookPath("conntrack"); err == nil {
			add(doctorCheck{ID: "tools.conntrack", Status: "pass", Message: "conntrack utility available for `clatch health --conntrack`"})
		} else {
			add(doctorCheck{
				ID:      "tools.conntrack",
				Status:  "warn",
				Message: "conntrack utility not found (optional)",
				Hint:    "Install `conntrack` if you plan to run `clatch health --conntrack`.",
			})
		}
	}

	// 6. Existing configuration inspection
	if _, err := os.Stat(configPath); err == nil {
		if _, checkErr := checkConfig(configPath); checkErr != nil {
			add(doctorCheck{
				ID:      "config.debian",
				Status:  "fail",
				Message: fmt.Sprintf("Config %s failed validation: %v", configPath, checkErr),
				Hint:    fmt.Sprintf("Run `clatch config check --config %s` for details.", configPath),
			})
		} else {
			add(doctorCheck{ID: "config.debian", Status: "pass", Message: fmt.Sprintf("Installed gateway config %s and approved policy are valid", configPath)})
		}
	} else if configExplicit {
		add(doctorCheck{
			ID:      "config.debian",
			Status:  "fail",
			Message: fmt.Sprintf("Explicit config not found at %s", configPath),
			Hint:    "Check the --config path or run `clatch init profile` to create an install profile.",
		})
	} else if _, err := os.Stat("/etc/jdn-gateway/config.json"); err == nil {
		add(doctorCheck{
			ID:      "config.legacy",
			Status:  "warn",
			Message: "Detected legacy Python gateway config at /etc/jdn-gateway/config.json",
			Hint:    "Run `clatch migrate plan` to adopt the legacy gateway, or pass `--config /etc/jdn-gateway/config.json`.",
		})
	}

	// 7. Optional OpenWrt config check
	checkOWRT := openwrtPath
	if checkOWRT == "" {
		if _, err := os.Stat(openwrt.DefaultConfigPath); err == nil {
			checkOWRT = openwrt.DefaultConfigPath
		}
	}
	if checkOWRT != "" {
		if _, err := openwrt.ReadConfig(checkOWRT); err != nil {
			add(doctorCheck{
				ID:      "config.openwrt",
				Status:  "fail",
				Message: fmt.Sprintf("OpenWrt config %s failed validation: %v", checkOWRT, err),
				Hint:    "Run `clatch schema openwrt` to inspect required fields.",
			})
		} else {
			add(doctorCheck{ID: "config.openwrt", Status: "pass", Message: fmt.Sprintf("OpenWrt config %s is valid", checkOWRT)})
		}
	}

	// 8. Optional Debian install profile check
	if profilePath != "" {
		for _, pc := range deploy.CheckInstallProfile(profilePath) {
			add(doctorCheck{ID: pc.ID, Status: pc.Status, Message: pc.Message, Hint: pc.Hint})
		}
	}

	report.Passed = report.Summary.Fail == 0

	// Suggest helpful next steps based on findings
	if profilePath != "" && report.Passed {
		report.NextSteps = append(report.NextSteps,
			fmt.Sprintf("clatch install plan %s", profilePath),
			fmt.Sprintf("clatch install apply %s /root/clatch-install", profilePath),
		)
	} else if _, err := os.Stat(configPath); err == nil {
		report.NextSteps = append(report.NextSteps,
			fmt.Sprintf("clatch status --config %s", configPath),
			fmt.Sprintf("clatch health --config %s", configPath),
		)
	} else if checkOWRT != "" {
		report.NextSteps = append(report.NextSteps, fmt.Sprintf("clatch openwrt status --config %s", checkOWRT))
	} else if errors.Is(errNoFile(configPath), os.ErrNotExist) {
		report.NextSteps = append(report.NextSteps,
			"clatch init profile --backend xray-core --output /root/gateway-profile.json",
			"clatch schema --list",
		)
	}

	return report
}

func errNoFile(path string) error {
	_, err := os.Stat(path)
	return err
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

func (r doctorReport) text() string {
	var out strings.Builder
	banner := "PASSED"
	if !r.Passed {
		banner = "FAILED"
	}
	fmt.Fprintf(&out, "Clatch doctor: %s (pass=%d warn=%d fail=%d)\n\n", banner, r.Summary.Pass, r.Summary.Warn, r.Summary.Fail)
	for _, c := range r.Checks {
		tag := strings.ToUpper(c.Status)
		fmt.Fprintf(&out, "[%-4s] %-22s %s\n", tag, c.ID, c.Message)
		if c.Hint != "" {
			fmt.Fprintf(&out, "       hint: %s\n", c.Hint)
		}
	}
	if len(r.NextSteps) > 0 {
		out.WriteString("\nNext steps:\n")
		for _, step := range r.NextSteps {
			fmt.Fprintf(&out, "  %s\n", step)
		}
	}
	return out.String()
}
