//go:build !linux

package main

import (
	"fmt"
	"io"
	"net/netip"
	"runtime"

	"clatch-gateway/internal/deploy"
	"clatch-gateway/internal/policy"
)

func tryRunDiagnostic(args []string, _ io.Writer) (int, bool) {
	return 0, false
}

func runPlatformCommand(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errUsage
	}
	switch args[0] {
	case "openwrt":
		if len(args) >= 2 && args[1] == "check" {
			return runOpenWrtCheck(args[2:])
		}
		if len(args) >= 2 {
			switch args[1] {
			case "install", "status", "prepare", "verify", "tproxy-start", "tproxy-stop":
				return nil, unsupportedPlatformError("openwrt " + args[1])
			}
		}
		return nil, errUsage
	case "status", "health", "stats", "guard", "install", "upgrade", "uninstall",
		"whitelist", "policy", "diagnostic", "bpf", "native", "tproxy", "managed-tun":
		return nil, unsupportedPlatformError(topicFor(args))
	default:
		return nil, errUsage
	}
}

func detectHostNetwork() (string, string, string, string) {
	return "", "", "", ""
}

func explainLiveKernel(_ netip.Addr, _ string) (policy.Verdict, error) {
	return policy.Verdict{}, unsupportedPlatformError("explain --live")
}

func runHostDoctorChecks(report *doctorReport, _ string) {
	report.add(doctorCheck{
		ID:      "platform.offline",
		Status:  "pass",
		Message: fmt.Sprintf("Running Clatch offline verifier on %s/%s", runtime.GOOS, runtime.GOARCH),
		Hint:    "Kernel/runtime checks (TCX, nftables, bpffs, systemd) run on Linux targets.",
	})
}

func checkDoctorProfile(path string) []doctorCheck {
	raw := deploy.CheckInstallProfileSchema(path)
	out := make([]doctorCheck, 0, len(raw))
	for _, c := range raw {
		out = append(out, doctorCheck{ID: c.ID, Status: c.Status, Message: c.Message, Hint: c.Hint})
	}
	return out
}
