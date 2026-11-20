//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"clatch-gateway/internal/deploy"
	"clatch-gateway/internal/gateway"
	"clatch-gateway/internal/native"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
)

type serviceStatus struct {
	Unit   string `json:"unit"`
	Active string `json:"active"`
	Sub    string `json:"substate"`
	kind   string
	result string
}

type statusReport struct {
	State         string                       `json:"state"`
	Config        string                       `json:"config"`
	Interface     string                       `json:"interface,omitempty"`
	Backend       string                       `json:"backend,omitempty"`
	Mode          string                       `json:"mode,omitempty"`
	Services      []serviceStatus              `json:"services,omitempty"`
	Guard         map[string]any               `json:"guard,omitempty"`
	GuardVerified bool                         `json:"guard_verified"`
	PolicySHA     string                       `json:"network_sha256,omitempty"`
	Tunnel        string                       `json:"tunnel,omitempty"`
	TunnelBound   bool                         `json:"tunnel_bound"`
	Deployment    *deploy.Status               `json:"deployment,omitempty"`
	PendingPolicy *gateway.PendingPolicyStatus `json:"pending_policy,omitempty"`
	Issues        []string                     `json:"issues,omitempty"`
}

func runStatus(args []string) (any, error) {
	options, err := readOptions("status", args, false)
	if err != nil {
		return nil, err
	}
	report, err := localStatus(options.config, options.explicit)
	result := inspection{value: report}
	if !options.json {
		result.text = report.text()
	}
	return result, err
}

func localStatus(path string, explicit bool) (statusReport, error) {
	report := statusReport{Config: path, State: "unconfigured"}
	config, err := policy.ReadConfig(path)
	if errors.Is(err, os.ErrNotExist) && !explicit {
		return report, nil
	}
	if err != nil {
		report.State = "unknown"
		report.issues("configuration", err)
		return report, err
	}
	report.State, report.Interface = "healthy", config.Interface
	report.Backend, report.Mode = config.NativeService, "tproxy"
	backend := config.NativeService
	if config.Proxy != nil {
		report.Backend, backend = config.Proxy.Kind, config.Proxy.Service
	}
	if config.IsTUN() {
		report.Mode, report.Tunnel = "tun", config.TUNDevice()
		if config.NativeTUN {
			report.Mode = "native-tun"
		}
	}
	for _, unit := range []string{deploy.GuardUnit, backend} {
		service, err := readServiceStatus(unit)
		report.Services = append(report.Services, service)
		report.issues(unit, err)
		if err == nil && service.Active != "active" {
			report.issues(unit, fmt.Errorf("service is %s", service.Active))
		}
	}
	report.Guard, err = gateway.Verify(path)
	report.GuardVerified = err == nil
	report.issues("guard", err)
	index, _ := report.Guard["trusted_tun_ifindex"].(uint32)
	report.TunnelBound = index > 0
	if err == nil && config.IsTUN() && !report.TunnelBound {
		report.issues("tunnel", fmt.Errorf("%s is not bound", report.Tunnel))
	}
	approved, err := config.ReadApproved()
	report.issues("policy", err)
	report.PolicySHA = approved.NetworkSHA256
	if err == nil && config.IsNative() {
		report.issues("native policy", native.CheckApproved(config, approved))
		report.issues("native capture", native.VerifyCapture(config, approved))
	}
	report.Deployment, err = deploy.LocalStatus(config)
	report.issues("deployment", err)
	report.PendingPolicy, err = gateway.PendingPolicy(config, path)
	report.issues("policy transaction", err)
	if len(report.Issues) > 0 {
		report.State = "degraded"
	} else if report.PendingPolicy != nil || report.Deployment != nil && report.Deployment.State != "confirmed" {
		report.State = "pending"
	}
	return report, nil
}

func readServiceStatus(unit string) (serviceStatus, error) {
	if !strings.HasSuffix(unit, ".service") {
		unit += ".service"
	}
	status := serviceStatus{Unit: unit}
	raw, err := system.Command("", "systemctl", "show", "--property=ActiveState,SubState,Type,Result", unit)
	if err != nil {
		return status, err
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "ActiveState":
			status.Active = value
		case "SubState":
			status.Sub = value
		case "Type":
			status.kind = value
		case "Result":
			status.result = value
		}
	}
	if status.Active == "" {
		return status, fmt.Errorf("service state unavailable")
	}
	return status, nil
}

func (r *statusReport) issues(component string, err error) {
	if err != nil {
		r.Issues = append(r.Issues, component+": "+err.Error())
	}
}

func (r statusReport) text() string {
	var out strings.Builder
	fmt.Fprintf(&out, "Clatch is %s\nConfiguration  %s\n", r.State, r.Config)
	if r.Interface != "" {
		fmt.Fprintf(&out, "Interface      %s\nProxy          %s (%s)\n", r.Interface, r.Backend, r.Mode)
	}
	for _, service := range r.Services {
		state := fmt.Sprintf("%s (%s)", service.Active, service.Sub)
		if service.kind == "oneshot" && service.result == "success" && service.Active == "active" && service.Sub == "exited" {
			state = "startup task completed"
		}
		fmt.Fprintf(&out, "Service        %s %s\n", service.Unit, state)
	}
	if r.GuardVerified {
		fmt.Fprintln(&out, "Guard          nftables and TCX verified")
	}
	if r.Tunnel != "" {
		state := "unbound"
		if r.TunnelBound {
			state = "bound"
		}
		fmt.Fprintf(&out, "Tunnel         %s %s\n", r.Tunnel, state)
	}
	if r.PolicySHA != "" {
		fmt.Fprintf(&out, "Policy         %s\n", r.PolicySHA[:12])
	}
	if r.Deployment != nil {
		fmt.Fprintf(&out, "Deployment     %s %s\nBackup         %s\n", r.Deployment.Kind, r.Deployment.State, r.Deployment.Backup)
		if r.Deployment.RollbackDeadline != nil {
			fmt.Fprintf(&out, "Rollback due   %s\n", r.Deployment.RollbackDeadline.Format("2006-01-02 15:04:05 MST"))
		}
	}
	if r.PendingPolicy != nil {
		fmt.Fprintf(&out, "Policy change  %s (%s)\n", r.PendingPolicy.State, r.PendingPolicy.Directory)
		if r.PendingPolicy.RollbackDeadline != nil {
			fmt.Fprintf(&out, "Rollback due   %s\n", r.PendingPolicy.RollbackDeadline.Format("2006-01-02 15:04:05 MST"))
		}
	}
	for _, issue := range r.Issues {
		fmt.Fprintf(&out, "Issue          %s\n", issue)
	}
	return out.String()
}
