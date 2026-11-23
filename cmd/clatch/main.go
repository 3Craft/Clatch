package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	errUsage               = errors.New("invalid arguments")
	errUnsupportedPlatform = errors.New("command requires Linux")
)

func main() {
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr))
}

func execute(args []string, stdout, stderr io.Writer) int {
	if code, handled := tryRunDiagnostic(args, stderr); handled {
		return code
	}
	if len(args) >= 1 && (args[0] == "--version" || args[0] == "-v") {
		args = append([]string{"version"}, args[1:]...)
	}
	jsonRequested := wantJSON(args)
	if topic, requested := helpTopic(args); requested {
		if jsonRequested {
			if manifest, ok := buildHelpManifest(topic); ok {
				if err := json.NewEncoder(stdout).Encode(manifest); err != nil {
					fmt.Fprintf(stderr, "clatch: %v\n", err)
					return 1
				}
				return 0
			}
		}
		if help := commandHelp(topic); help != "" {
			fmt.Fprint(stdout, help)
			return 0
		}
		err := usageError("unknown command %q", topic)
		writeError(stdout, stderr, topic, err, jsonRequested, false)
		return 2
	}
	result, err := run(args)
	wroteStdout := false
	switch output := result.(type) {
	case inspection:
		var writeErr error
		if !jsonRequested && output.text != "" {
			_, writeErr = io.WriteString(stdout, output.text)
			wroteStdout = true
		} else if output.value != nil {
			writeErr = json.NewEncoder(stdout).Encode(output.value)
			wroteStdout = true
		} else if output.text != "" {
			_, writeErr = io.WriteString(stdout, output.text)
			wroteStdout = true
		}
		err = errors.Join(err, writeErr)
	default:
		if err == nil && result != nil {
			err = json.NewEncoder(stdout).Encode(result)
			wroteStdout = true
		}
	}
	if err != nil {
		topic := topicFor(args)
		writeError(stdout, stderr, topic, err, jsonRequested, wroteStdout)
		if errors.Is(err, errUsage) {
			return 2
		}
		return 1
	}
	return 0
}

func writeError(stdout, stderr io.Writer, topic string, err error, jsonRequested, wroteStdout bool) {
	detail := classifyError(err, topic)
	if jsonRequested && !wroteStdout {
		_ = json.NewEncoder(stdout).Encode(jsonErrorEnvelope{
			OK:      false,
			Passed:  false,
			Command: topic,
			Error:   err.Error(),
			Detail:  detail,
		})
	}
	if errors.Is(err, errUsage) {
		if commandHelp(topic) == "" {
			fmt.Fprintf(stderr, "clatch: unknown command %q. Run clatch --help.\n", topic)
		} else {
			fmt.Fprintf(stderr, "clatch: %v. Run clatch %s --help.\n", err, topic)
		}
		return
	}
	fmt.Fprintf(stderr, "clatch: %v\n", err)
	if !jsonRequested && detail.Hint != "" {
		fmt.Fprintf(stderr, "hint: %s\n", detail.Hint)
	}
}

func run(args []string) (any, error) {
	if filepath.Base(os.Args[0]) == "guardctl" {
		return runPlatformCommand(append([]string{"bpf"}, args...))
	}
	if len(args) == 0 {
		return nil, errUsage
	}
	switch args[0] {
	case "doctor":
		return runDoctor(args[1:])
	case "explain":
		return runExplain(args[1:])
	case "init":
		return runInit(args[1:])
	case "schema":
		return runSchema(args[1:])
	case "version":
		return runVersion(args[1:])
	case "config":
		return runConfig(args[1:])
	case "nft":
		return runNFT(args[1:])
	default:
		return runPlatformCommand(args)
	}
}
