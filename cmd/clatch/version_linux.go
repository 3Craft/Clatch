//go:build linux

package main

import (
	"fmt"
	"runtime"
	"strings"

	"clatch-gateway/internal/guard"
)

// Build metadata injected via -ldflags at release time.
var (
	version = "dev"
	commit  = ""
)

type versionInfo struct {
	Version          string `json:"version"`
	Commit           string `json:"commit,omitempty"`
	GoVersion        string `json:"go_version"`
	GOOS             string `json:"goos"`
	GOARCH           string `json:"goarch"`
	EmbeddedBPF      bool   `json:"embedded_bpf"`
	CLISchemaVersion int    `json:"cli_schema_version"`
}

func currentVersion() versionInfo {
	return versionInfo{
		Version:          version,
		Commit:           commit,
		GoVersion:        runtime.Version(),
		GOOS:             runtime.GOOS,
		GOARCH:           runtime.GOARCH,
		EmbeddedBPF:      guard.EmbeddedBPF(),
		CLISchemaVersion: 1,
	}
}

func runVersion(args []string) (any, error) {
	var options inspectionOptions
	flags := options.flags("version")
	if err := flags.Parse(args); err != nil {
		return nil, usageError("%v", err)
	}
	if flags.NArg() != 0 {
		return nil, usageError("unexpected arguments")
	}
	if err := options.resolveFormat(flags); err != nil {
		return nil, err
	}
	info := currentVersion()
	result := inspection{value: info}
	if !options.json {
		result.text = info.text()
	}
	return result, nil
}

func (v versionInfo) text() string {
	var out strings.Builder
	ver := v.Version
	if v.Commit != "" {
		ver += " (" + v.Commit + ")"
	}
	fmt.Fprintf(&out, "Clatch %s (%s/%s, %s)\n", ver, v.GOOS, v.GOARCH, v.GoVersion)
	bpfState := "external"
	if v.EmbeddedBPF {
		bpfState = "embedded"
	}
	fmt.Fprintf(&out, "BPF object     %s\n", bpfState)
	fmt.Fprintf(&out, "CLI schema     v%d\n", v.CLISchemaVersion)
	return out.String()
}
