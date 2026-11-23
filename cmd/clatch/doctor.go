package main

import (
	"fmt"
	"os"
	"strings"

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

func (r *doctorReport) add(c doctorCheck) {
	r.Checks = append(r.Checks, c)
	switch c.Status {
	case "pass":
		r.Summary.Pass++
	case "warn":
		r.Summary.Warn++
	case "fail":
		r.Summary.Fail++
	}
}

func runDoctor(args []string) (any, error) {
	var options inspectionOptions
	var profilePath, openwrtPath string
	flags := options.flags("doctor")
	flags.StringVar(&profilePath, "profile", "", "install profile JSON to validate")
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
	runHostDoctorChecks(&report, profilePath)

	// Gateway configuration validation
	if _, err := os.Stat(configPath); err == nil {
		if _, checkErr := checkConfig(configPath); checkErr != nil {
			report.add(doctorCheck{
				ID:      "config.gateway",
				Status:  "fail",
				Message: fmt.Sprintf("Config %s failed validation: %v", configPath, checkErr),
				Hint:    fmt.Sprintf("Run `clatch config check --config %s` for details.", configPath),
			})
		} else {
			report.add(doctorCheck{ID: "config.gateway", Status: "pass", Message: fmt.Sprintf("Gateway config %s and approved policy are valid", configPath)})
		}
	} else if configExplicit {
		report.add(doctorCheck{
			ID:      "config.gateway",
			Status:  "fail",
			Message: fmt.Sprintf("Explicit config not found at %s", configPath),
			Hint:    "Check the --config path or run `clatch init profile` to create an install profile.",
		})
	}

	// OpenWrt configuration validation
	checkOWRT := openwrtPath
	if checkOWRT == "" {
		if _, err := os.Stat(openwrt.DefaultConfigPath); err == nil {
			checkOWRT = openwrt.DefaultConfigPath
		}
	}
	if checkOWRT != "" {
		if _, err := openwrt.ReadConfig(checkOWRT); err != nil {
			report.add(doctorCheck{
				ID:      "config.openwrt",
				Status:  "fail",
				Message: fmt.Sprintf("OpenWrt config %s failed validation: %v", checkOWRT, err),
				Hint:    "Run `clatch schema openwrt` to inspect required fields.",
			})
		} else {
			report.add(doctorCheck{ID: "config.openwrt", Status: "pass", Message: fmt.Sprintf("OpenWrt config %s is valid", checkOWRT)})
		}
	}

	// Profile validation (platform-specific: full host check on Linux, schema-only offline on macOS)
	if profilePath != "" {
		for _, pc := range checkDoctorProfile(profilePath) {
			report.add(pc)
		}
	}

	report.Passed = report.Summary.Fail == 0

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
	} else {
		report.NextSteps = append(report.NextSteps,
			"clatch init profile --backend xray-core --output /root/gateway-profile.json",
			"clatch schema --list",
		)
	}
	return report
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
