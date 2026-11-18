//go:build linux

package capture

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"clatch-gateway/internal/gateway"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/proxy"
	"clatch-gateway/internal/system"
)

const (
	tableName   = "jdn_v2ray_tproxy"
	routeTable  = "10048"
	rulePref    = 10048
	statePath   = "/run/jdn-v2ray-tproxy.json"
	defaultPort = 12345
)

type state struct {
	Config string `json:"config"`
	Port   uint16 `json:"port"`
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
		if _, err := gate.Verify(); err != nil {
			return err
		}
		actual, err := listener(gate.Config, port)
		if err != nil {
			return err
		}
		abs, err := filepath.Abs(configPath)
		if err != nil {
			return err
		}
		path, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return err
		}
		owner = state{Config: path, Port: actual}
		rules := render(policy.Elements(gate.Approved.Prefixes, 32), actual)
		return start(owner, rules)
	})
	return owner, err
}

func StopTPROXY() error {
	return gateway.WithLock(func() error {
		_, owned, err := readState()
		if err != nil {
			return err
		}
		kernel, err := inspect()
		if err != nil {
			return err
		}
		if !owned && kernel != (reserved{}) {
			return fmt.Errorf("unowned TPROXY state exists")
		}
		if owned {
			return stop(kernel)
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

func readState() (state, bool, error) {
	data, err := os.ReadFile(statePath)
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
	if !filepath.IsAbs(owner.Config) || owner.Port < 1024 {
		return state{}, false, fmt.Errorf("invalid TPROXY ownership record")
	}
	return owner, true, nil
}

func start(owner state, rules string) error {
	prior, owned, err := readState()
	if err != nil {
		return err
	}
	kernel, err := inspect()
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
		if err := system.WriteAtomic(statePath, append(data, '\n'), 0600); err != nil {
			return err
		}
	}
	previous := kernel
	err = install(&kernel, rules)
	if err == nil {
		return nil
	}
	// Roll back only the resources this start attempt added.
	added := reserved{routes: kernel.routes - previous.routes, rules: kernel.rules - previous.rules, nft: kernel.nft && !previous.nft}
	recovery := remove(added)
	if !owned && recovery == nil {
		recovery = os.Remove(statePath)
	}
	return errors.Join(err, recovery)
}

func install(kernel *reserved, rules string) error {
	if kernel.routes == 0 {
		if _, err := system.Command("", "ip", "-4", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", routeTable); err != nil {
			return err
		}
		kernel.routes = 1
	}
	if kernel.rules == 0 {
		if _, err := system.Command("", "ip", "-4", "rule", "add", "priority", routeTable, "fwmark", "0x40/0xc0", "lookup", routeTable); err != nil {
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

func stop(kernel reserved) error {
	if err := remove(kernel); err != nil {
		return err
	}
	return os.Remove(statePath)
}

func remove(kernel reserved) error {
	if kernel.nft {
		if _, err := system.Command("", "nft", "delete", "table", "inet", tableName); err != nil {
			return err
		}
	}
	if kernel.rules != 0 {
		if _, err := system.Command("", "ip", "-4", "rule", "del", "priority", routeTable, "fwmark", "0x40/0xc0", "lookup", routeTable); err != nil {
			return err
		}
	}
	if kernel.routes != 0 {
		if _, err := system.Command("", "ip", "-4", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", routeTable); err != nil {
			return err
		}
	}
	return nil
}

func inspect() (reserved, error) {
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
		if object.Table.Name == tableName && object.Table.Family == "inet" {
			resources.nft = true
		}
	}
	if err := inspectRoutes(&resources); err != nil {
		return resources, err
	}
	if err := inspectRules(&resources); err != nil {
		return resources, err
	}
	return resources, nil
}

func inspectRoutes(resources *reserved) error {
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
		if strings.Trim(string(route.Table), "\"") != routeTable {
			continue
		}
		if resources.routes != 0 || route.Type != "local" || route.Dev != "lo" ||
			route.Dst != "default" && route.Dst != "0.0.0.0/0" {
			return fmt.Errorf("reserved TPROXY routing table contains an unrecognized route")
		}
		resources.routes++
	}
	return nil
}

func inspectRules(resources *reserved) error {
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
		if rule.Priority != rulePref {
			continue
		}
		if resources.rules != 0 || rule.Src != "all" || rule.Mark != "0x40" || rule.Mask != "0xc0" ||
			strings.Trim(string(rule.Table), "\"") != routeTable {
			return fmt.Errorf("reserved TPROXY rule priority is occupied")
		}
		resources.rules++
	}
	return nil
}

func render(direct string, port uint16) string {
	return fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
 set direct4 { type ipv4_addr; flags interval; auto-merge; elements = { %[2]s }; }
 chain prerouting {
  type filter hook prerouting priority mangle; policy accept;
  meta nfproto != ipv4 return
  meta mark & 0x80 != 0 return
  ip daddr @direct4 return
  meta l4proto { tcp, udp } meta mark set 0x40 tproxy ip to 127.0.0.1:%[3]d accept
 }
 chain output {
  type route hook output priority mangle; policy accept;
  meta nfproto != ipv4 return
  meta mark & 0x80 != 0 return
  ip daddr @direct4 return
  meta l4proto { tcp, udp } meta mark set 0x40
 }
}
`, tableName, direct, port)
}
