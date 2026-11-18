//go:build linux

package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"clatch-gateway/internal/device"
	"clatch-gateway/internal/firewall"
	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/native"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/proxy"
	"clatch-gateway/internal/system"
)

const lock = "/run/lock/jdn-gateway-guard.lock"

func WithLock(action func() error) error {
	return system.WithLock(lock, action)
}

type Gate struct {
	Config   policy.Config
	Approved policy.Approved
	Path     string
}

func OpenStandalone(path string) (*Gate, error) {
	gate, err := open(path)
	if err == nil && gate.Config.Proxy == nil {
		return nil, fmt.Errorf("capture requires a standalone backend")
	}
	return gate, err
}

func open(path string) (*Gate, error) {
	config, err := policy.ReadConfig(path)
	if err != nil {
		return nil, err
	}
	if config.Proxy == nil && !config.NativeTUN {
		return nil, fmt.Errorf("guard requires a standalone backend or native v2rayA TUN")
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(config.ApprovedPolicy), "pending-transaction.json")); err == nil {
		return nil, fmt.Errorf("recover pending policy transaction before starting")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	approved, err := config.ReadApproved()
	if err != nil {
		return nil, err
	}
	if config.Proxy != nil {
		if err := verifySource(config, approved, path); err != nil {
			return nil, err
		}
		if config.Proxy.Kind == "mihomo" {
			if _, err := proxy.ReadMihomo(config); err != nil {
				return nil, err
			}
		}
	}
	return &Gate{Config: config, Approved: approved, Path: path}, nil
}

func Ensure(path, iface string) (map[string]any, error) {
	if !policy.ValidInterface(iface) {
		return nil, fmt.Errorf("startup requires a valid trusted gate interface")
	}
	var result map[string]any
	err := WithLock(func() error {
		var err error
		result, err = ensure(path, iface)
		if err != nil {
			return errors.Join(err, closeGate(iface))
		}
		return nil
	})
	return result, err
}

func ensure(path, iface string) (map[string]any, error) {
	config, err := policy.ReadConfig(path)
	if err != nil {
		return nil, err
	}
	if config.Interface != iface {
		return nil, fmt.Errorf("configured interface differs from trusted gate")
	}
	if config.Proxy != nil {
		if err := recoverPolicy(config, path); err != nil {
			return nil, err
		}
	}
	gate, err := open(path)
	if err != nil {
		return nil, err
	}
	if gate.Config.NativeTUN {
		if err := gate.recoverNative(); err != nil {
			return nil, err
		}
	}
	if err := checkFilters(iface); err != nil {
		return nil, err
	}
	if err := system.MountBPF(); err != nil {
		return nil, err
	}
	_, statErr := os.Lstat(filepath.Join(gate.Config.Pins, "link"))
	create := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !create {
		return nil, statErr
	}
	settings, err := gate.settings(create)
	if gate.Config.NativeTUN && !create {
		if err != nil {
			if revokeErr := gate.switchNative(native.Snapshot{}); revokeErr != nil {
				return nil, errors.Join(err, revokeErr)
			}
			settings, err = gate.settings(false)
		} else {
			active, readErr := guard.Dump(gate.Config.Pins)
			if readErr != nil {
				return nil, readErr
			}
			if active.TrustedTUNIfindex != settings.TrustedTUNIfindex {
				if err := gate.switchNative(native.Snapshot{}); err != nil {
					return nil, err
				}
				settings.TrustedTUNIfindex = 0
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if create {
		if _, err := guard.Attach(iface, "-", gate.Config.Pins, gate.Config.Entries(gate.Approved), settings); err != nil {
			return nil, err
		}
	}
	if _, err := gate.verifyTCX(settings); err != nil {
		return nil, err
	}
	rules, err := firewall.RenderGuard(gate.Config, gate.Approved, settings.TrustedTUNIfindex)
	if err != nil {
		return nil, err
	}
	if err := firewall.Apply(rules, gate.Config.RulesFile, gate.fingerprintPath()); err != nil {
		return nil, err
	}
	result, err := gate.Verify()
	if err != nil {
		return nil, err
	}
	if err := gate.applyProbeRoutes(); err != nil {
		return nil, err
	}
	return result, openGate(iface, gate.Config.IsTUN())
}

func Verify(path string) (map[string]any, error) {
	var result map[string]any
	err := WithLock(func() error {
		gate, err := open(path)
		if err != nil {
			return err
		}
		result, err = gate.Verify()
		return err
	})
	return result, err
}

func (g *Gate) fingerprintPath() string {
	return filepath.Join(filepath.Dir(g.Config.ApprovedPolicy), "clatch-nft.sha256")
}

func (g *Gate) settings(create bool) (guard.Settings, error) {
	settings := guard.Settings{DiagnosticUID: g.Config.DiagnosticUID}
	if !g.Config.IsTUN() {
		return settings, nil
	}
	if g.Config.NativeTUN {
		if create {
			return settings, native.Publish(native.Snapshot{})
		}
		identity, err := native.Identity(g.Config)
		settings.TrustedTUNIfindex = identity.Ifindex
		return settings, err
	}
	read := device.VerifyManaged
	if create {
		read = device.PrepareManaged
	}
	identity, err := read()
	settings.TrustedTUNIfindex = identity.Ifindex
	return settings, err
}

func (g *Gate) verifyTCX(settings guard.Settings) (map[string]any, error) {
	verify := guard.VerifyStandalone
	if g.Config.IsTUN() {
		verify = guard.Verify
	}
	info, err := verify(g.Config.Interface, g.Config.Pins)
	if err != nil {
		return nil, err
	}
	mapID, err := guard.CheckPolicy(g.Config.Pins, g.Config.Entries(g.Approved), settings)
	if err != nil {
		return nil, err
	}
	counters, err := guard.Stats(g.Config.Pins)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"ifindex": info.Ifindex, "link_id": info.LinkID, "program_id": info.ProgramID,
		"map_id": mapID, "network_sha256": g.Approved.NetworkSHA256,
		"diagnostic_uid": g.Config.DiagnosticUID, "trusted_tun_ifindex": settings.TrustedTUNIfindex,
		"public_ipv6": false, "stats": counters,
	}, nil
}

func (g *Gate) Verify() (map[string]any, error) {
	settings, err := g.settings(false)
	if err != nil {
		return nil, err
	}
	result, err := g.verifyTCX(settings)
	if err != nil {
		return nil, err
	}
	if err := checkFilters(g.Config.Interface); err != nil {
		return nil, err
	}
	rules, err := firewall.RenderGuard(g.Config, g.Approved, settings.TrustedTUNIfindex)
	if err != nil {
		return nil, err
	}
	if err := firewall.Verify(rules, g.fingerprintPath()); err != nil {
		return nil, err
	}
	return result, nil
}

func (g *Gate) applyProbeRoutes() error {
	for _, route := range g.Config.ProbeRoutes {
		destination, err := netip.ParsePrefix(route.Destination)
		via, viaErr := netip.ParseAddr(route.Via)
		if err != nil || viaErr != nil || !destination.Addr().Is4() || destination.Bits() != 32 ||
			!via.Is4() || !policy.Match(g.Config.LANPrefixes, netip.PrefixFrom(via, 32)) ||
			policy.Match(g.Approved.Prefixes, destination) {
			return fmt.Errorf("invalid isolated observation route")
		}
		if _, err := system.Command("", "ip", "link", "set", "dev", g.Config.Interface, "up"); err != nil {
			return err
		}
		if _, err := system.Command("", "ip", "route", "replace", destination.String(), "via", via.String(), "dev", g.Config.Interface, "onlink"); err != nil {
			return err
		}
	}
	return nil
}

func checkFilters(iface string) error {
	rawFilters, err := system.Command("", "tc", "-j", "filter", "show", "dev", iface, "egress")
	if err != nil {
		return err
	}
	var filters []json.RawMessage
	if err := json.Unmarshal(rawFilters, &filters); err != nil {
		return err
	}
	if len(filters) != 0 {
		return fmt.Errorf("legacy TC egress filters already protect %s", iface)
	}
	rawLinks, err := system.Command("", "ip", "-j", "-details", "link", "show", "dev", iface)
	if err != nil {
		return err
	}
	var links []struct {
		XDP struct {
			Attached string `json:"attached"`
		} `json:"xdp"`
	}
	if err := json.Unmarshal(rawLinks, &links); err != nil {
		return err
	}
	if len(links) != 1 || links[0].XDP.Attached != "" && links[0].XDP.Attached != "off" {
		return fmt.Errorf("interface has an unreviewed XDP program")
	}
	return nil
}

func openGate(iface string, tun bool) error {
	if _, err := system.Command("", "sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=0"); err != nil {
		return err
	}
	var keys []string
	for _, scope := range []string{"all", "default", iface} {
		if tun {
			keys = append(keys, "net/ipv4/conf/"+scope+"/rp_filter=0")
		}
		for _, key := range []string{"send_redirects", "accept_redirects", "secure_redirects"} {
			keys = append(keys, "net/ipv4/conf/"+scope+"/"+key+"=0")
		}
		for _, key := range []string{"accept_ra", "accept_redirects"} {
			keys = append(keys, "net/ipv6/conf/"+scope+"/"+key+"=0")
		}
	}
	_, err := system.Command("", "sysctl", append([]string{"-q", "-w"}, keys...)...)
	return err
}

func closeGate(iface string) error {
	_, forward := system.Command("", "sysctl", "-q", "-w", "net.ipv4.ip_forward=0", "net.ipv6.conf.all.forwarding=0")
	_, down := system.Command("", "ip", "link", "set", "dev", strings.TrimSpace(iface), "down")
	return errors.Join(forward, down)
}
