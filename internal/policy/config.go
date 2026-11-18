package policy

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"

	"clatch-gateway/internal/guard"
)

var (
	interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	serviceName   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]*$`)
)

type Diagnostic struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type Proxy struct {
	Kind         string `json:"kind"`
	Mode         string `json:"mode"`
	Service      string `json:"service"`
	Binary       string `json:"binary"`
	Config       string `json:"config"`
	PolicySource string `json:"policy_source"`
	DNSAddress   string `json:"dns_address"`
	DNSPort      uint16 `json:"dns_port"`
}

type ProbeRoute struct {
	Destination string `json:"destination"`
	Via         string `json:"via"`
}

type Config struct {
	Interface      string       `json:"interface"`
	DiagnosticUID  uint32       `json:"diagnostic_uid"`
	PublicIPv6     bool         `json:"public_ipv6"`
	NativeTUN      bool         `json:"native_tun"`
	Pins           string       `json:"pins"`
	ApprovedPolicy string       `json:"policy"`
	RulesFile      string       `json:"rules_file"`
	Libexec        string       `json:"libexec"`
	NativeConfDir  string       `json:"native_confdir"`
	NativeService  string       `json:"native_service"`
	LAN            []string     `json:"lan"`
	Local          []string     `json:"local"`
	Diagnostic     *Diagnostic  `json:"lan_icmp_diagnostic"`
	Proxy          *Proxy       `json:"proxy"`
	ProbeRoutes    []ProbeRoute `json:"probe_routes"`

	LANPrefixes   []netip.Prefix `json:"-"`
	LocalPrefixes []netip.Prefix `json:"-"`
}

func ReadConfig(path string) (Config, error) {
	var config Config
	err := readJSON(path, &config, true)
	if err == nil {
		err = config.Validate()
	}
	return config, err
}

func ValidInterface(name string) bool {
	return interfaceName.MatchString(name) && name != "." && name != ".."
}

func filePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

func (c *Config) Validate() error {
	if !ValidInterface(c.Interface) || c.DiagnosticUID == 0 ||
		c.DiagnosticUID == 65534 || c.DiagnosticUID == ^uint32(0) ||
		c.PublicIPv6 || c.NativeTUN && c.Proxy != nil {
		return fmt.Errorf("invalid egress interface, diagnostic identity, IPv6 or TUN mode")
	}
	if !filePath(c.Pins) || !filePath(c.ApprovedPolicy) ||
		(c.RulesFile != "" && !filePath(c.RulesFile)) {
		return fmt.Errorf("guard paths must be canonical absolute paths")
	}
	if c.NativeConfDir == "" {
		c.NativeConfDir = "/etc/v2raya"
	}
	if c.NativeService == "" {
		c.NativeService = "v2raya"
	}
	if !filePath(c.NativeConfDir) || !serviceName.MatchString(c.NativeService) {
		return fmt.Errorf("invalid native manager configuration")
	}
	var err error
	if c.LANPrefixes, err = Parse(c.LAN); err != nil {
		return err
	}
	if c.LocalPrefixes, err = Parse(c.Local); err != nil {
		return err
	}
	if Elements(c.LANPrefixes, 32) == "" || Elements(c.LocalPrefixes, 32) == "" {
		return fmt.Errorf("IPv4 LAN and local addresses are required")
	}
	for _, prefix := range c.LocalPrefixes {
		if prefix.Bits() != prefix.Addr().BitLen() || !Match(c.LANPrefixes, prefix) {
			return fmt.Errorf("local address %s must be a host in the LAN", prefix)
		}
	}
	if c.Proxy != nil {
		if err := c.Proxy.validate(); err != nil {
			return err
		}
	}
	if c.IsTUN() {
		network := netip.MustParsePrefix("172.31.255.0/30")
		if c.NativeTUN {
			network = netip.MustParsePrefix("10.0.85.0/30")
		}
		for _, prefix := range c.LANPrefixes {
			if prefix.Overlaps(network) {
				return fmt.Errorf("TUN address overlaps LAN %s", prefix)
			}
		}
	}
	if c.Diagnostic != nil {
		if !c.NativeTUN {
			return fmt.Errorf("LAN diagnostics require native TUN")
		}
		source, sourceErr := ipv4Host(c.Diagnostic.Source)
		destination, destErr := ipv4Host(c.Diagnostic.Destination)
		if sourceErr != nil || destErr != nil || !Match(c.LANPrefixes, source) ||
			Match(c.LANPrefixes, destination) || Match(c.LocalPrefixes, source) ||
			!usableLANHost(c.LANPrefixes, source.Addr()) {
			return fmt.Errorf("diagnostic pair must use a LAN client and a distinct off-LAN destination")
		}
	}
	return nil
}

func ipv4Host(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	addr := prefix.Addr()
	if err != nil || !addr.Is4() || prefix.Bits() != 32 || !addr.IsGlobalUnicast() {
		return netip.Prefix{}, fmt.Errorf("expected unicast IPv4 address %q", value)
	}
	return prefix, nil
}

func usableLANHost(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			if prefix.Bits() >= 31 {
				return true
			}
			network := prefix.Addr().As4()
			host := addr.As4()
			first := binary.BigEndian.Uint32(network[:])
			last := first | (uint32(1)<<(32-prefix.Bits()) - 1)
			value := binary.BigEndian.Uint32(host[:])
			if value > first && value < last {
				return true
			}
		}
	}
	return false
}

func (p *Proxy) validate() error {
	if p.Mode == "" {
		p.Mode = "tproxy"
	}
	switch p.Kind {
	case "mihomo":
		if p.Mode != "tproxy" && p.Mode != "tun" {
			return fmt.Errorf("invalid mihomo interception mode %q", p.Mode)
		}
	case "v2ray-core", "xray-core":
		if p.Mode != "tproxy" {
			return fmt.Errorf("invalid standalone interception mode %q", p.Mode)
		}
	default:
		return fmt.Errorf("unknown standalone backend %q", p.Kind)
	}
	dns, err := netip.ParseAddr(p.DNSAddress)
	if err != nil || !dns.Is4() || !dns.IsLoopback() || p.DNSPort == 0 {
		return fmt.Errorf("standalone backend needs an IPv4 loopback DNS endpoint")
	}
	if !serviceName.MatchString(p.Service) || !filePath(p.Binary) ||
		!filePath(p.Config) || !filePath(p.PolicySource) {
		return fmt.Errorf("standalone backend service or paths are invalid")
	}
	return nil
}

func (c Config) IsTUN() bool {
	return c.NativeTUN || c.Proxy != nil && c.Proxy.Mode == "tun"
}

func (c Config) TUNDevice() string {
	if c.NativeTUN {
		return "tun0"
	}
	if c.IsTUN() {
		return "jdn-tun"
	}
	return ""
}

type Approved struct {
	Schema        int             `json:"schema"`
	Created       string          `json:"created,omitempty"`
	Networks      []string        `json:"networks"`
	NetworkSHA256 string          `json:"network_sha256"`
	ProxyKind     string          `json:"proxy_kind,omitempty"`
	ProxyMode     string          `json:"proxy_mode,omitempty"`
	NativeMode    string          `json:"native_mode,omitempty"`
	Whitelist     json.RawMessage `json:"native_whitelist,omitempty"`
	GeoIP         string          `json:"geoip,omitempty"`
	GeoIPSHA256   string          `json:"geoip_sha256,omitempty"`
	Transition    json.RawMessage `json:"transition,omitempty"`
	SourcePolicy  json.RawMessage `json:"source_policy,omitempty"`
	SourceSHA256  string          `json:"source_sha256,omitempty"`

	Prefixes []netip.Prefix `json:"-"`
}

func (c Config) ReadApproved() (Approved, error) {
	var approved Approved
	if err := readJSON(c.ApprovedPolicy, &approved, false); err != nil {
		return Approved{}, err
	}
	return c.ValidateApproved(approved)
}

func (c Config) ValidateApproved(approved Approved) (Approved, error) {
	prefixes, err := Parse(approved.Networks)
	if err != nil {
		return Approved{}, err
	}
	if Elements(prefixes, 32) == "" || Digest(prefixes) != approved.NetworkSHA256 {
		return Approved{}, fmt.Errorf("approved policy is empty or its digest differs")
	}
	if c.Proxy != nil {
		mode := approved.ProxyMode
		if mode == "" {
			mode = "tproxy"
		}
		if approved.Schema != 2 || c.Proxy.Kind != approved.ProxyKind || c.Proxy.Mode != mode {
			return Approved{}, fmt.Errorf("approved policy belongs to a different standalone backend")
		}
	} else if approved.Schema != 1 || c.NativeTUN != (approved.NativeMode == "tun") {
		return Approved{}, fmt.Errorf("approved policy belongs to a different native mode")
	}
	for _, lan := range c.LANPrefixes {
		if !Match(prefixes, lan) {
			return Approved{}, fmt.Errorf("LAN %s is missing from the approved policy", lan)
		}
	}
	approved.Prefixes = prefixes
	return approved, nil
}

func (c Config) Entries(approved Approved) guard.Policy {
	entries := make(guard.Policy, len(approved.Prefixes)+len(c.LANPrefixes)+len(c.LocalPrefixes)+2)
	for _, prefix := range approved.Prefixes {
		entries[toKey(prefix)] = guard.Direct
	}
	for _, prefix := range c.LANPrefixes {
		entries[toKey(prefix)] = guard.Direct | guard.LAN
	}
	for _, prefix := range c.LocalPrefixes {
		entries[toKey(prefix)] = guard.Direct | guard.LAN | guard.Local
	}
	if c.Diagnostic != nil {
		source, _ := ipv4Host(c.Diagnostic.Source)
		destination, _ := ipv4Host(c.Diagnostic.Destination)
		entries[toKey(source)] = guard.Direct | guard.LAN | guard.DiagnosticClient
		flags := guard.DiagnosticDestination
		if Match(approved.Prefixes, destination) {
			flags |= guard.Direct
		}
		entries[toKey(destination)] = flags
	}
	return entries
}

func toKey(prefix netip.Prefix) guard.Key {
	family := uint32(6)
	if prefix.Addr().Is4() {
		family = 4
	}
	key := guard.Key{Family: family, PrefixLen: uint32(prefix.Bits() + 32)}
	copy(key.Address[:], prefix.Addr().AsSlice())
	return key
}

func readJSON(path string, dest any, strict bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(dest); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("%s: trailing JSON data", path)
	}
	return nil
}
