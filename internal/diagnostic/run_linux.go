//go:build linux

package diagnostic

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"clatch-gateway/internal/policy"
)

var physicalInterface = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,14}$`)

func Run(kind, configPath string, args []string) (int, error) {
	if os.Geteuid() != 0 {
		return 2, fmt.Errorf("root is required for the restricted diagnostic account")
	}
	config, err := policy.ReadConfig(configPath)
	if err != nil {
		return 2, err
	}
	account, err := user.Lookup("jdn-trace")
	if err != nil {
		return 2, err
	}
	if account.Uid != strconv.FormatUint(uint64(config.DiagnosticUID), 10) {
		return 2, fmt.Errorf("diagnostic account does not match the approved UID")
	}
	program, families, err := diagnosticArgs(kind, config.Interface, args)
	if err != nil {
		return 2, err
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return 2, err
	}
	unit := fmt.Sprintf("clatch-%s-%d-%x.service", kind, os.Getpid(), suffix)
	cmdArgs := []string{
		"--unit=" + unit, "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
		"-p", "User=jdn-trace", "-p", "Group=jdn-trace",
		"-p", "CapabilityBoundingSet=CAP_NET_RAW", "-p", "AmbientCapabilities=CAP_NET_RAW",
		"-p", "NoNewPrivileges=yes", "-p", "RestrictAddressFamilies=" + families,
		"-p", "ProtectSystem=strict", "-p", "ProtectHome=yes", "-p", "PrivateDevices=yes",
		"-p", "KillSignal=SIGINT", "-p", "TimeoutStopSec=5s",
	}
	command := exec.Command("/usr/bin/systemd-run", append(cmdArgs, program...)...)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(interrupted)
	if err := command.Start(); err != nil {
		return 2, err
	}
	defer stop(unit)
	result := make(chan error, 1)
	go func() { result <- command.Wait() }()
	select {
	case err := <-result:
		if exited, ok := err.(*exec.ExitError); ok {
			status := exited.Sys().(syscall.WaitStatus)
			if status.Signaled() {
				return 128 + int(status.Signal()), nil
			}
			return exited.ExitCode(), nil
		}
		return 0, err
	case received := <-interrupted:
		stop(unit)
		_ = command.Process.Kill()
		<-result
		return 128 + int(received.(syscall.Signal)), nil
	}
}

func stop(unit string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", unit).Run()
}

func diagnosticArgs(kind, iface string, args []string) ([]string, string, error) {
	families := "AF_INET AF_INET6 AF_UNIX"
	switch kind {
	case "ping":
		if !physicalInterface.MatchString(iface) || iface == "lo" {
			return nil, "", fmt.Errorf("invalid physical interface for IPv4 ping")
		}
		for _, arg := range args {
			if arg == "--" {
				break
			}
			if arg == "-6" || strings.HasPrefix(arg, "-I") || strings.HasPrefix(arg, "-m") {
				return nil, "", fmt.Errorf("IPv4 gateway ping fixes the interface and socket routing")
			}
		}
		return append([]string{"/usr/bin/ping", "-4", "-I", iface}, args...), families + " AF_NETLINK", nil
	case "traceroute":
		command := []string{"/usr/bin/traceroute.db"}
		explicit := false
		for _, arg := range args {
			if arg == "--" {
				break
			}
			if arg == "--fwmark" || strings.HasPrefix(arg, "--fwmark=") {
				explicit = true
			}
		}
		if !explicit {
			command = append(command, "--fwmark=128")
		}
		return append(command, args...), families, nil
	default:
		return nil, "", fmt.Errorf("unknown gateway diagnostic %q", kind)
	}
}
