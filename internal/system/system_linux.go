//go:build linux

package system

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// TimerDeadline reads the next scheduled activation of an existing systemd timer.
func TimerDeadline(unit string) (*time.Time, error) {
	raw, err := Command("", "systemctl", "list-timers", "--all", "--output=json", "--no-pager", unit)
	if err != nil {
		return nil, err
	}
	var timers []struct {
		Unit string `json:"unit"`
		Next uint64 `json:"next"`
	}
	if err := json.Unmarshal(raw, &timers); err != nil {
		return nil, fmt.Errorf("read timer %s: %w", unit, err)
	}
	for _, timer := range timers {
		if timer.Unit == unit && timer.Next > 0 && timer.Next <= uint64(1<<63-1) {
			deadline := time.UnixMicro(int64(timer.Next)).UTC()
			return &deadline, nil
		}
	}
	return nil, nil
}

func Command(input string, command string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, command, args...)
	if input != "" {
		process.Stdin = strings.NewReader(input)
	}
	out, err := process.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, fmt.Errorf("%s %s: %w: %s", command, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".clatch-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func WithLock(path string, action func() error) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	return action()
}

func MountBPF() error {
	const mount = "/sys/fs/bpf"
	var stats unix.Statfs_t
	if err := unix.Statfs(mount, &stats); err != nil {
		return err
	}
	if stats.Type == unix.BPF_FS_MAGIC {
		return nil
	}
	return unix.Mount("bpf", mount, "bpf", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=700")
}
