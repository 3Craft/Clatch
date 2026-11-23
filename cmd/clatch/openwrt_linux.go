//go:build linux

package main

import (
	"fmt"
	"strconv"
	"strings"

	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/openwrt"
)

func runOpenWrt(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errUsage
	}
	switch args[0] {
	case "check":
		return runOpenWrtCheck(args[1:])
	case "install":
		return runOpenWrtInstall(args[1:])
	case "status":
		return runOpenWrtStatus(args[1:])
	case "prepare":
		pos, asJSON, err := splitSimpleFlags("openwrt prepare", args[1:])
		if err != nil || len(pos) != 3 {
			if err != nil {
				return nil, err
			}
			return nil, errUsage
		}
		info, err := openwrt.Prepare(pos[0], pos[1], pos[2])
		if err != nil {
			return nil, err
		}
		return formatOpenWrtLink("prepared", pos[1], pos[2], info, asJSON), nil
	case "verify":
		pos, asJSON, err := splitSimpleFlags("openwrt verify", args[1:])
		if err != nil || len(pos) != 3 {
			if err != nil {
				return nil, err
			}
			return nil, errUsage
		}
		info, err := openwrt.Verify(pos[0], pos[1], pos[2])
		if err != nil {
			return nil, err
		}
		return formatOpenWrtLink("verified", pos[1], pos[2], info, asJSON), nil
	case "tproxy-start":
		pos, asJSON, err := splitSimpleFlags("openwrt tproxy-start", args[1:])
		if err != nil || len(pos) != 2 {
			if err != nil {
				return nil, err
			}
			return nil, errUsage
		}
		port, err := strconv.ParseUint(pos[1], 10, 16)
		if err != nil {
			return nil, usageError("invalid TPROXY port %q", pos[1])
		}
		if err := openwrt.StartTPROXY(pos[0], uint16(port)); err != nil {
			return nil, err
		}
		res := inspection{value: map[string]any{"state": "started", "config": pos[0], "port": uint16(port)}}
		if !asJSON {
			res.text = fmt.Sprintf("OpenWrt TPROXY capture started on port %d (%s)\n", port, pos[0])
		}
		return res, nil
	case "tproxy-stop":
		pos, asJSON, err := splitSimpleFlags("openwrt tproxy-stop", args[1:])
		if err != nil || len(pos) != 0 {
			if err != nil {
				return nil, err
			}
			return nil, errUsage
		}
		if err := openwrt.StopTPROXY(); err != nil {
			return nil, err
		}
		res := inspection{value: map[string]any{"state": "stopped"}}
		if !asJSON {
			res.text = "OpenWrt TPROXY capture stopped (WAN egress guard remains active)\n"
		}
		return res, nil
	}
	return nil, errUsage
}

func runOpenWrtInstall(args []string) (any, error) {
	var options inspectionOptions
	var protoDir string
	var dryRun bool
	flags := options.flags("openwrt install")
	flags.StringVar(&protoDir, "proto-dir", "/lib/netifd/proto", "netifd protocol handler directory")
	flags.BoolVar(&dryRun, "dry-run", false, "preview files without writing")
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if err := options.resolve(flags, ""); err != nil {
		return nil, err
	}
	if !options.explicit {
		options.config = openwrt.DefaultConfigPath
	}
	result, err := openwrt.Install(openwrt.InstallOptions{
		ConfigPath: options.config,
		ProtoDir:   protoDir,
		DryRun:     dryRun,
	})
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	if result.Applied {
		fmt.Fprintln(&out, "OpenWrt protocol handlers installed")
	} else {
		fmt.Fprintln(&out, "OpenWrt install preview (dry run)")
	}
	fmt.Fprintf(&out, "Configuration  %s\nProto dir      %s\n", result.Config, result.ProtoDir)
	for _, f := range result.Files {
		fmt.Fprintf(&out, "File           %s\n", f)
	}
	if len(result.NextSteps) > 0 {
		out.WriteString("\nNext steps:\n")
		for _, step := range result.NextSteps {
			fmt.Fprintf(&out, "  %s\n", step)
		}
	}
	res := inspection{value: result}
	if !options.json {
		res.text = out.String()
	}
	return res, nil
}

func runOpenWrtStatus(args []string) (any, error) {
	options, err := readOptions("openwrt status", args, true)
	if err != nil {
		return nil, err
	}
	if !options.explicit {
		options.config = openwrt.DefaultConfigPath
	}
	report, err := openwrt.Status(options.config)
	res := inspection{value: report}
	if !options.json {
		res.text = formatOpenWrtStatus(report)
	}
	return res, err
}

func formatOpenWrtLink(action, logical, device string, info guard.LinkInfo, asJSON bool) inspection {
	res := inspection{value: info}
	if !asJSON {
		res.text = fmt.Sprintf("OpenWrt uplink %s (%s) %s\nTCX            link=%d prog=%d ifindex=%d\n",
			logical, device, action, info.LinkID, info.ProgramID, info.Ifindex)
	}
	return res
}

func formatOpenWrtStatus(r openwrt.StatusReport) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Clatch OpenWrt is %s\nConfiguration  %s\n", r.State, r.Config)
	if r.Policy != "" {
		fmt.Fprintf(&out, "Policy         %s (%d direct networks)\n", r.Policy, r.DirectNetworks)
	}
	if len(r.LANDevices) > 0 {
		fmt.Fprintf(&out, "LAN devices    %s\n", strings.Join(r.LANDevices, ", "))
	}
	if r.ProxyDevice != "" {
		fmt.Fprintf(&out, "Proxy device   %s\n", r.ProxyDevice)
	}
	if len(r.UnmanagedEgressDevices) > 0 {
		fmt.Fprintf(&out, "Unmanaged      %s\n", strings.Join(r.UnmanagedEgressDevices, ", "))
	}
	for _, u := range r.Uplinks {
		if u.Verified {
			allow, deny := summarizeCounters(u.Stats)
			fmt.Fprintf(&out, "Uplink         %s (%s) verified (allow=%d deny=%d)\n", u.Network, u.Device, allow, deny)
		} else {
			fmt.Fprintf(&out, "Uplink         %s (%s) failed: %s\n", u.Network, u.Device, u.Error)
		}
	}
	for _, issue := range r.Issues {
		fmt.Fprintf(&out, "Issue          %s\n", issue)
	}
	return out.String()
}
