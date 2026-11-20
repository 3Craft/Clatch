//go:build linux

package main

import (
	"flag"
	"fmt"
	"io"
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
}

func (o *inspectionOptions) flags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&o.config, "config", "", "gateway configuration")
	flags.BoolVar(&o.json, "json", false, "write a JSON report")
	return flags
}

func (o *inspectionOptions) resolve(flags *flag.FlagSet, positional string) error {
	flags.Visit(func(flag *flag.Flag) {
		if flag.Name == "config" {
			o.explicit = true
		}
	})
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

func checkReport(options inspectionOptions, data map[string]any, err error) (inspection, error) {
	if data == nil {
		data = make(map[string]any)
	}
	if options.json || err != nil {
		data["passed"], data["config"] = err == nil, options.config
	}
	if err != nil {
		data["error"] = err.Error()
	}
	return inspection{value: data}, err
}
