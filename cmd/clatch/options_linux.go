//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"clatch-gateway/internal/policy"
)

// An inspection may return a report together with a failed-check exit status.
type inspection struct {
	value any
	text  string
}

type inspectionOptions struct {
	config   string
	explicit bool
	json     bool
	format   string
}

type errorDetail struct {
	Code      string   `json:"code"`
	Message   string   `json:"message"`
	Hint      string   `json:"hint,omitempty"`
	NextSteps []string `json:"next_steps,omitempty"`
	Retryable bool     `json:"retryable,omitempty"`
}

type jsonErrorEnvelope struct {
	OK      bool        `json:"ok"`
	Passed  bool        `json:"passed"`
	Command string      `json:"command,omitempty"`
	Error   string      `json:"error"`
	Detail  errorDetail `json:"error_detail"`
}

func defaultJSONOutput() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("CLATCH_FORMAT")), "json")
}

// wantJSON inspects raw CLI arguments (before "--") plus CLATCH_FORMAT to
// determine whether structured JSON output was requested.
func wantJSON(args []string) bool {
	jsonMode := defaultJSONOutput()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		switch {
		case arg == "--json" || arg == "-json" || arg == "--json=true" || arg == "-json=true":
			jsonMode = true
		case arg == "--json=false" || arg == "-json=false":
			jsonMode = false
		case arg == "--format" || arg == "-format":
			if i+1 < len(args) {
				i++
				if strings.EqualFold(args[i], "json") {
					jsonMode = true
				} else if strings.EqualFold(args[i], "text") {
					jsonMode = false
				}
			}
		case strings.HasPrefix(arg, "--format=") || strings.HasPrefix(arg, "-format="):
			_, val, _ := strings.Cut(arg, "=")
			if strings.EqualFold(val, "json") {
				jsonMode = true
			} else if strings.EqualFold(val, "text") {
				jsonMode = false
			}
		}
	}
	return jsonMode
}

func (o *inspectionOptions) flags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&o.config, "config", "", "gateway configuration")
	flags.BoolVar(&o.json, "json", false, "write a JSON report")
	flags.StringVar(&o.format, "format", "", "output format: text or json")
	return flags
}

func (o *inspectionOptions) resolveFormat(flags *flag.FlagSet) error {
	jsonSet := false
	formatSet := false
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "json":
			jsonSet = true
		case "format":
			formatSet = true
		}
	})
	if formatSet {
		switch strings.ToLower(strings.TrimSpace(o.format)) {
		case "json":
			if jsonSet && !o.json {
				return usageError("conflicting --json=false and --format=json")
			}
			o.json = true
		case "text":
			if jsonSet && o.json {
				return usageError("conflicting --json and --format=text")
			}
			o.json = false
		default:
			return usageError("invalid --format %q (expected text or json)", o.format)
		}
	} else if !jsonSet {
		o.json = defaultJSONOutput()
	}
	return nil
}

func (o *inspectionOptions) resolve(flags *flag.FlagSet, positional string) error {
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			o.explicit = true
		}
	})
	if err := o.resolveFormat(flags); err != nil {
		return err
	}
	if o.explicit && (o.config == "" || positional != "") {
		return usageError("supply one non-empty configuration path")
	}
	if positional != "" {
		o.config, o.explicit = positional, true
	} else if o.config == "" {
		o.config = policy.DefaultConfigPath
	}
	return nil
}

func readOptions(name string, args []string, allowPositional bool) (inspectionOptions, error) {
	var options inspectionOptions
	flags := options.flags(name)
	var positional string
	if allowPositional && len(args) > 0 && args[0] != "" && !strings.HasPrefix(args[0], "-") {
		positional, args = args[0], args[1:]
	}
	if err := flags.Parse(args); err != nil {
		return options, usageError("%v", err)
	}
	if flags.NArg() == 1 && allowPositional && positional == "" && flags.Arg(0) != "" {
		positional = flags.Arg(0)
	} else if flags.NArg() != 0 {
		return options, usageError("unexpected arguments")
	}
	return options, options.resolve(flags, positional)
}

func usageError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errUsage, fmt.Sprintf(format, args...))
}

func checkReport(options inspectionOptions, data map[string]any, text string, err error) (inspection, error) {
	if data == nil {
		data = make(map[string]any)
	}
	if options.json || err != nil {
		data["passed"], data["config"] = err == nil, options.config
	}
	if err != nil {
		data["error"] = err.Error()
		detail := classifyError(err, "")
		if detail.Code != "" {
			data["error_code"] = detail.Code
		}
		if detail.Hint != "" {
			data["hint"] = detail.Hint
		}
	}
	out := inspection{value: data}
	if !options.json {
		out.text = text
	}
	return out, err
}

func classifyError(err error, topic string) errorDetail {
	if err == nil {
		return errorDetail{}
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	detail := errorDetail{Code: "OPERATION_FAILED", Message: msg}
	switch {
	case errors.Is(err, errUsage):
		detail.Code = "INVALID_ARGUMENTS"
		if topic != "" && commandHelp(topic) != "" {
			detail.Hint = fmt.Sprintf("Run `clatch %s --help` to see valid usage and options.", topic)
			detail.NextSteps = []string{fmt.Sprintf("clatch %s --help", topic)}
		} else {
			detail.Hint = "Run `clatch --help` to see available commands."
			detail.NextSteps = []string{"clatch --help"}
		}
	case errors.Is(err, os.ErrPermission) || strings.Contains(lower, "requires root") || strings.Contains(lower, "permission denied"):
		detail.Code = "PERMISSION_DENIED"
		detail.Hint = "Run this command as root (for example with sudo)."
	case errors.Is(err, os.ErrNotExist) || strings.Contains(lower, "no such file or directory"):
		detail.Code = "NOT_FOUND"
		detail.Hint = "Verify the file path or run `clatch doctor` to inspect local configuration."
		detail.NextSteps = []string{"clatch doctor"}
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded") || strings.Contains(lower, "timed out"):
		detail.Code = "TIMEOUT"
		detail.Retryable = true
		detail.Hint = "The operation timed out; check service/network readiness and retry."
	case strings.Contains(lower, "unknown field"):
		detail.Code = "INVALID_CONFIG_SCHEMA"
		detail.Hint = "Check the allowed JSON fields with `clatch schema --list`."
		detail.NextSteps = []string{"clatch schema --list"}
	}
	return detail
}
