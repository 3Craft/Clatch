//go:build linux

package main

import (
	"fmt"
	"net/netip"
	"strings"

	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/openwrt"
	"clatch-gateway/internal/policy"
)

type explainReport struct {
	Target      string          `json:"target"`
	Mode        string          `json:"mode"`
	Config      string          `json:"config"`
	PolicySHA   string          `json:"network_sha256,omitempty"`
	Verdict     policy.Verdict  `json:"verdict"`
	LiveChecked bool            `json:"live_checked,omitempty"`
	LiveVerdict *policy.Verdict `json:"live_verdict,omitempty"`
	LiveMatches *bool           `json:"live_matches,omitempty"`
	LiveError   string          `json:"live_error,omitempty"`
	NextSteps   []string        `json:"next_steps,omitempty"`
}

func runExplain(args []string) (any, error) {
	var options inspectionOptions
	var openwrtPath string
	var live bool
	flags := options.flags("explain")
	flags.StringVar(&openwrtPath, "openwrt", "", "OpenWrt gateway configuration file")
	flags.BoolVar(&live, "live", false, "also inspect the live kernel TCX LPM trie")

	var target string
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) && target == "" {
				target = args[i+1]
				if i+2 < len(args) {
					return nil, usageError("unexpected arguments")
				}
			}
			break
		}
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if (arg == "--config" || arg == "-config" || arg == "--openwrt" || arg == "-openwrt" ||
				arg == "--format" || arg == "-format") && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		if target != "" {
			return nil, usageError("supply a single IP address to explain")
		}
		target = arg
	}
	if err := flags.Parse(flagArgs); err != nil {
		return nil, usageError("%v", err)
	}
	if err := options.resolve(flags, ""); err != nil {
		return nil, err
	}
	if target == "" {
		return nil, usageError("missing IP address")
	}
	addr, err := netip.ParseAddr(target)
	if err != nil {
		return nil, usageError("invalid IP address %q", target)
	}
	if openwrtPath != "" && options.explicit {
		return nil, usageError("use either --config or --openwrt, not both")
	}

	var report explainReport
	if openwrtPath != "" {
		cfg, err := openwrt.ReadConfig(openwrtPath)
		if err != nil {
			return nil, err
		}
		entries := cfg.PolicyEntries()
		verdict := policy.Explain(addr, entries)
		report = explainReport{
			Target:  addr.String(),
			Mode:    "openwrt",
			Config:  openwrtPath,
			Verdict: verdict,
		}
	} else {
		cfg, err := policy.ReadConfig(options.config)
		if err != nil {
			return nil, err
		}
		approved, err := cfg.ReadApproved()
		if err != nil {
			return nil, err
		}
		entries := cfg.Entries(approved)
		verdict := policy.Explain(addr, entries)
		report = explainReport{
			Target:    addr.String(),
			Mode:      "debian",
			Config:    options.config,
			PolicySHA: approved.NetworkSHA256,
			Verdict:   verdict,
		}
		if live {
			report.LiveChecked = true
			active, err := guard.Dump(cfg.Pins)
			if err != nil {
				report.LiveError = err.Error()
			} else {
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
				lv := policy.Explain(addr, liveEntries)
				report.LiveVerdict = &lv
				matches := lv.Decision == verdict.Decision && lv.MatchedPrefix == verdict.MatchedPrefix && lv.FlagMask == verdict.FlagMask
				report.LiveMatches = &matches
			}
		}
		if !verdict.AllowedDirect && addr.Is4() {
			if cfg.IsNative() {
				report.NextSteps = []string{
					fmt.Sprintf("clatch whitelist add %s/32", addr),
				}
			} else if cfg.Proxy != nil {
				report.NextSteps = []string{
					fmt.Sprintf("Add %s/32 to %s and apply with `clatch policy stage`", addr, cfg.Proxy.PolicySource),
				}
			}
		}
	}

	res := inspection{value: report}
	if !options.json {
		res.text = report.text()
	}
	if report.LiveError != "" {
		return res, fmt.Errorf("live kernel TCX check failed: %s", report.LiveError)
	}
	return res, nil
}

func (r explainReport) text() string {
	var out strings.Builder
	fmt.Fprintf(&out, "Target         %s\n", r.Target)
	fmt.Fprintf(&out, "Decision       %s\n", r.Verdict.Decision)
	fmt.Fprintf(&out, "Direct egress  %t\n", r.Verdict.AllowedDirect)
	if r.Verdict.MatchedPrefix != "" {
		fmt.Fprintf(&out, "Matched CIDR   %s (%s)\n", r.Verdict.MatchedPrefix, strings.Join(r.Verdict.Flags, ", "))
	} else {
		fmt.Fprintf(&out, "Matched CIDR   (none)\n")
	}
	fmt.Fprintf(&out, "Explanation    %s\n", r.Verdict.Explanation)
	fmt.Fprintf(&out, "Configuration  %s (%s)\n", r.Config, r.Mode)
	if r.PolicySHA != "" {
		short := r.PolicySHA
		if len(short) > 12 {
			short = short[:12]
		}
		fmt.Fprintf(&out, "Policy SHA     %s\n", short)
	}
	if r.LiveChecked {
		if r.LiveError != "" {
			fmt.Fprintf(&out, "Live kernel    error: %s\n", r.LiveError)
		} else if r.LiveMatches != nil && *r.LiveMatches {
			fmt.Fprintf(&out, "Live kernel    matches approved policy\n")
		} else if r.LiveVerdict != nil {
			fmt.Fprintf(&out, "Live kernel    DRIFT detected (live decision: %s, prefix: %s)\n", r.LiveVerdict.Decision, r.LiveVerdict.MatchedPrefix)
		}
	}
	for i, step := range r.NextSteps {
		if i == 0 {
			fmt.Fprintf(&out, "To allow       %s\n", step)
		} else {
			fmt.Fprintf(&out, "               %s\n", step)
		}
	}
	return out.String()
}
