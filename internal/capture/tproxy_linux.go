//go:build linux

package capture

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"clatch-gateway/internal/gateway"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/proxy"
	"clatch-gateway/internal/system"
)

const defaultPort = 12345

type mode struct {
	table       string
	priority    string
	routeDevice string
	statePath   string
	local       bool
}

var tproxy = mode{
	table: "clatch_tproxy", priority: "10048", routeDevice: "lo",
	statePath: "/run/clatch-tproxy.json", local: true,
}

var routedTPROXY = mode{
	table: "clatch_openwrt_tproxy", priority: tproxy.priority, routeDevice: "lo",
	statePath: "/var/run/clatch-openwrt-tproxy.json", local: true,
}

type state struct {
	Config    string `json:"config"`
	Port      uint16 `json:"port,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Ifindex   uint32 `json:"ifindex,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type reserved struct {
	routes int
	rules  int
	nft    bool
}

func StartTPROXY(configPath string, port uint16) (state, error) {
	var owner state
	err := gateway.WithLock(func() error {
		gate, err := gateway.OpenStandalone(configPath)
		if err != nil {
			return err
		}
		if gate.Config.IsTUN() {
			return fmt.Errorf("TPROXY capture requires standalone TPROXY mode")
		}
		if _, err := gate.Verify(); err != nil {
			return err
		}
		actual, err := listener(gate.Config, port)
		if err != nil {
			return err
		}
		path, err := resolve(configPath)
		if err != nil {
			return err
		}
		owner = state{Config: path, Port: actual}
		rules := renderTPROXY(policy.Elements(gate.Approved.Prefixes, 32), actual)
		return tproxy.start(owner, rules, managedTUN)
	})
	return owner, err
}

func StopTPROXY() error {
	return stopMode(tproxy)
}

func StartRoutedTPROXY(configPath string, port uint16, lanDevices, lan4, direct4 string) error {
	path, err := resolve(configPath)
	if err != nil {
		return err
	}
	owner := state{Config: path, Port: port}
	rules := renderRoutedTPROXY(lanDevices, lan4, direct4, port)
	return gateway.WithLock(func() error {
		return routedTPROXY.start(owner, rules, managedTUN)
	})
}

func StopRoutedTPROXY() error {
	return stopMode(routedTPROXY)
}

func resolve(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func stopMode(capture mode) error {
	return gateway.WithLock(func() error {
		_, owned, err := capture.readState()
		if err != nil {
			return err
		}
		kernel, err := capture.inspect()
		if err != nil {
			return err
		}
		if !owned && kernel != (reserved{}) {
			return fmt.Errorf("unowned TPROXY state exists")
		}
		if owned {
			return capture.stop(kernel)
		}
		return nil
	})
}

func listener(config policy.Config, requested uint16) (uint16, error) {
	if config.Proxy.Kind == "mihomo" {
		mihomo, err := proxy.ReadMihomo(config)
		if err != nil {
			return 0, err
		}
		if requested != 0 && requested != mihomo.TPROXYPort {
			return 0, fmt.Errorf("requested TPROXY port differs from the mihomo configuration")
		}
		return mihomo.TPROXYPort, nil
	}
	if requested == 0 {
		return defaultPort, nil
	}
	if requested < 1024 {
		return 0, fmt.Errorf("TPROXY port must be 1024 or higher")
	}
	return requested, nil
}

func (capture mode) readState() (state, bool, error) {
	data, err := os.ReadFile(capture.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return state{}, false, nil
	}
	if err != nil {
		return state{}, false, err
	}
	var owner state
	if err := json.Unmarshal(data, &owner); err != nil {
		return state{}, false, err
	}
	if !filepath.IsAbs(owner.Config) || capture.local && (owner.Port < 1024 || owner.Mode != "") ||
		!capture.local && (owner.Mode != "mihomo-managed-tun" || owner.Ifindex == 0 || owner.Port != 0 ||
			!policy.ValidInterface(owner.Interface)) {
		return state{}, false, fmt.Errorf("invalid TPROXY ownership record")
	}
	return owner, true, nil
}

func (capture mode) start(owner state, rules string, conflicting mode) error {
	if err := conflicting.requireIdle(); err != nil {
		return err
	}
	prior, owned, err := capture.readState()
	if err != nil {
		return err
	}
	kernel, err := capture.inspect()
	if err != nil {
		return err
	}
	if owned && prior != owner || !owned && kernel != (reserved{}) {
		return fmt.Errorf("reserved TPROXY resources already have another owner")
	}
	if _, err := system.Command(rules, "nft", "--check", "-f", "-"); err != nil {
		return err
	}
	if !owned {
		data, err := json.Marshal(owner)
		if err != nil {
			return err
		}
		if err := system.WriteAtomic(capture.statePath, append(data, '\n'), 0600); err != nil {
			return err
		}
	}
	previous := kernel
	err = capture.install(&kernel, rules)
	if err == nil {
		return nil
	}
	// Roll back only the resources this start attempt added.
	added := reserved{routes: kernel.routes - previous.routes, rules: kernel.rules - previous.rules, nft: kernel.nft && !previous.nft}
	recovery := capture.remove(added)
	if !owned && recovery == nil {
		recovery = os.Remove(capture.statePath)
	}
	return errors.Join(err, recovery)
}

func (capture mode) requireIdle() error {
	if _, present, err := capture.readState(); err != nil {
		return err
	} else if present {
		return fmt.Errorf("other transparent interception mode owns resources")
	}
	if kernel, err := capture.inspect(); err != nil {
		return err
	} else if kernel != (reserved{}) {
		return fmt.Errorf("conflicting transparent interception resources already exist")
	}
	return nil
}

func (capture mode) routeArgs(command string) []string {
	args := []string{"-4", "route", command}
	if capture.local {
		args = append(args, "local", "0.0.0.0/0")
	} else {
		args = append(args, "default")
	}
	return append(args, "dev", capture.routeDevice, "table", capture.priority)
}

func (capture mode) install(kernel *reserved, rules string) error {
	if !capture.local {
		if _, err := system.Command("", "ip", "link", "set", "dev", capture.routeDevice, "up"); err != nil {
			return err
		}
	}
	if kernel.routes == 0 {
		if _, err := system.Command("", "ip", capture.routeArgs("add")...); err != nil {
			return err
		}
		kernel.routes = 1
	}
	if kernel.rules == 0 {
		if _, err := system.Command("", "ip", "-4", "rule", "add", "priority", capture.priority, "fwmark", "0x40/0xc0", "lookup", capture.priority); err != nil {
			return err
		}
		kernel.rules = 1
	}
	if _, err := system.Command(rules, "nft", "-f", "-"); err != nil {
		return err
	}
	kernel.nft = true
	return nil
}

func (capture mode) stop(kernel reserved) error {
	if err := capture.remove(kernel); err != nil {
		return err
	}
	return os.Remove(capture.statePath)
}

func (capture mode) remove(kernel reserved) error {
	if kernel.nft {
		if _, err := system.Command("", "nft", "delete", "table", "inet", capture.table); err != nil {
			return err
		}
	}
	if kernel.rules != 0 {
		if _, err := system.Command("", "ip", "-4", "rule", "del", "priority", capture.priority, "fwmark", "0x40/0xc0", "lookup", capture.priority); err != nil {
			return err
		}
	}
	if kernel.routes != 0 {
		if _, err := system.Command("", "ip", capture.routeArgs("del")...); err != nil {
			return err
		}
	}
	return nil
}

func (capture mode) inspect() (reserved, error) {
	var resources reserved
	tables, err := system.Command("", "nft", "-j", "list", "tables")
	if err != nil {
		return resources, err
	}
	var list struct {
		Objects []struct {
			Table struct {
				Name   string `json:"name"`
				Family string `json:"family"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(tables, &list); err != nil {
		return resources, err
	}
	for _, object := range list.Objects {
		if object.Table.Name == capture.table && object.Table.Family == "inet" {
			resources.nft = true
		}
	}
	if err := capture.inspectRoutes(&resources); err != nil {
		return resources, err
	}
	if err := capture.inspectRules(&resources); err != nil {
		return resources, err
	}
	return resources, nil
}

func (capture mode) inspectRoutes(resources *reserved) error {
	data, err := system.Command("", "ip", "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return err
	}
	var routes []struct {
		Type  string          `json:"type"`
		Dst   string          `json:"dst"`
		Dev   string          `json:"dev"`
		Table json.RawMessage `json:"table"`
	}
	if err := json.Unmarshal(data, &routes); err != nil {
		return err
	}
	for _, route := range routes {
		if strings.Trim(string(route.Table), "\"") != capture.priority {
			continue
		}
		expectedType := ""
		if capture.local {
			expectedType = "local"
		}
		if resources.routes != 0 || route.Type != expectedType || route.Dev != capture.routeDevice ||
			route.Dst != "default" && route.Dst != "0.0.0.0/0" {
			return fmt.Errorf("reserved TPROXY routing table contains an unrecognized route")
		}
		resources.routes++
	}
	return nil
}

func (capture mode) inspectRules(resources *reserved) error {
	data, err := system.Command("", "ip", "-j", "-4", "rule", "show")
	if err != nil {
		return err
	}
	var rules []struct {
		Priority int             `json:"priority"`
		Src      string          `json:"src"`
		Mark     string          `json:"fwmark"`
		Mask     string          `json:"fwmask"`
		Table    json.RawMessage `json:"table"`
	}
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}
	for _, rule := range rules {
		if strconv.Itoa(rule.Priority) != capture.priority {
			continue
		}
		if resources.rules != 0 || rule.Src != "all" || rule.Mark != "0x40" || rule.Mask != "0xc0" ||
			strings.Trim(string(rule.Table), "\"") != capture.priority {
			return fmt.Errorf("reserved TPROXY rule priority is occupied")
		}
		resources.rules++
	}
	return nil
}

func renderTPROXY(direct string, port uint16) string {
	return fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
 set direct4 { type ipv4_addr; flags interval; auto-merge; elements = { %[2]s }; }
 chain prerouting {
  type filter hook prerouting priority mangle; policy accept;
  meta nfproto != ipv4 return
  meta mark & 0x80 != 0 return
  ip daddr 127.0.0.0/8 return
  ip daddr @direct4 return
  meta l4proto { tcp, udp } meta mark set 0x40 tproxy ip to 127.0.0.1:%[3]d accept
 }
 chain output {
  type route hook output priority mangle; policy accept;
  meta nfproto != ipv4 return
  meta mark & 0x80 != 0 return
  ip daddr 127.0.0.0/8 return
  ip daddr @direct4 return
  meta l4proto { tcp, udp } meta mark set 0x40
 }
}
`, tproxy.table, direct, port)
}

func renderRoutedTPROXY(lanDevices, lan4, direct4 string, port uint16) string {
	return fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
 set lan { type ifname; elements = { %[2]s }; }
 set lan4 { type ipv4_addr; flags interval; elements = { %[3]s }; }
 set direct4 { type ipv4_addr; flags interval; elements = { %[4]s }; }
 chain prerouting {
  type filter hook prerouting priority mangle; policy accept;
  meta nfproto != ipv4 return
  iifname != @lan return
  ip saddr != @lan4 return
  fib daddr type local return
  ip daddr @lan4 return
  ip daddr @direct4 return
  meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:%[5]d meta mark set (meta mark & 0xffffff3f) | 0x40 counter accept
 }
}
`, routedTPROXY.table, lanDevices, lan4, direct4, port)
}
