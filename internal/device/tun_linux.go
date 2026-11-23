//go:build linux

package device

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"clatch-gateway/internal/system"

	"golang.org/x/sys/unix"
)

const (
	ManagedTUN = "clatch-tun"
	statePath  = "/run/clatch-tun.json"
)

type Identity struct {
	Device  string `json:"device"`
	Ifindex uint32 `json:"ifindex"`
	BootID  string `json:"boot_id"`
	NetNS   uint64 `json:"netns"`
}

func contextIdentity(name string, index uint32) (Identity, error) {
	id, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return Identity{}, err
	}
	var ns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &ns); err != nil {
		return Identity{}, err
	}
	return Identity{Device: name, Ifindex: index, BootID: strings.TrimSpace(string(id)), NetNS: ns.Ino}, nil
}

func inspectManaged() (Identity, error) {
	output, err := system.Command("", "ip", "-j", "-details", "link", "show", "dev", ManagedTUN)
	if err != nil {
		return Identity{}, err
	}
	var links []struct {
		Ifindex  uint32 `json:"ifindex"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(output, &links); err != nil {
		return Identity{}, err
	}
	if len(links) != 1 || links[0].Ifindex == 0 || links[0].LinkInfo.Kind != "tun" {
		return Identity{}, fmt.Errorf("managed TUN name is occupied by another device type")
	}
	sysfs := filepath.Join("/sys/class/net", ManagedTUN)
	flagsData, err := os.ReadFile(filepath.Join(sysfs, "tun_flags"))
	if err != nil {
		return Identity{}, err
	}
	flags, err := strconv.ParseUint(strings.TrimSpace(string(flagsData)), 0, 32)
	if err != nil || flags&unix.IFF_TUN == 0 || flags&unix.IFF_TAP != 0 ||
		flags&unix.IFF_NO_PI == 0 || flags&unix.IFF_MULTI_QUEUE != 0 {
		return Identity{}, fmt.Errorf("managed TUN requires a single queue without packet-info headers")
	}
	for _, key := range []string{"owner", "group"} {
		owner, err := os.ReadFile(filepath.Join(sysfs, key))
		if err != nil {
			return Identity{}, err
		}
		if strings.TrimSpace(string(owner)) != "0" {
			return Identity{}, fmt.Errorf("managed TUN must be owned by root")
		}
	}
	details, err := system.Command("", "ip", "tuntap", "show", "dev", ManagedTUN)
	if err != nil {
		return Identity{}, err
	}
	persistent := false
	for _, field := range strings.Fields(string(details)) {
		persistent = persistent || field == "persist"
	}
	if !persistent {
		return Identity{}, fmt.Errorf("managed TUN must be persistent")
	}
	return contextIdentity(ManagedTUN, links[0].Ifindex)
}

func VerifyManaged() (Identity, error) {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return Identity{}, err
	}
	var expected Identity
	if err := json.Unmarshal(data, &expected); err != nil {
		return Identity{}, err
	}
	got, err := inspectManaged()
	if err != nil {
		return Identity{}, err
	}
	if got != expected {
		return Identity{}, fmt.Errorf("managed TUN identity changed; recovery requires a guarded reboot")
	}
	return got, nil
}

func PrepareManaged() (Identity, error) {
	if _, err := os.Stat(statePath); err == nil {
		return VerifyManaged()
	} else if !errors.Is(err, os.ErrNotExist) {
		return Identity{}, err
	}
	if _, err := net.InterfaceByName(ManagedTUN); err == nil {
		return Identity{}, fmt.Errorf("refusing to adopt an unowned managed TUN")
	}
	if _, err := system.Command("", "ip", "tuntap", "add", "dev", ManagedTUN, "mode", "tun", "user", "0", "group", "0"); err != nil {
		return Identity{}, err
	}
	if _, err := system.Command("", "sysctl", "-q", "-w",
		"net.ipv6.conf."+ManagedTUN+".disable_ipv6=1",
		"net.ipv4.conf."+ManagedTUN+".rp_filter=0",
		"net.ipv4.conf."+ManagedTUN+".send_redirects=0",
		"net.ipv4.conf."+ManagedTUN+".accept_redirects=0"); err != nil {
		return Identity{}, err
	}
	actual, err := inspectManaged()
	if err != nil {
		return Identity{}, err
	}
	data, err := json.Marshal(actual)
	if err != nil {
		return Identity{}, err
	}
	if err := system.WriteAtomic(statePath, append(data, '\n'), 0600); err != nil {
		return Identity{}, err
	}
	return actual, nil
}
