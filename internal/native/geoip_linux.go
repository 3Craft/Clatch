//go:build linux

package native

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"clatch-gateway/internal/policy"
)

type whitelist struct {
	Countries []string `json:"countryCodes"`
	Custom    []string `json:"customIps"`
}

// ReadWhitelist returns the complete SQLite value, including fields owned by v2rayA.
func ReadWhitelist(config policy.Config) (json.RawMessage, error) {
	var current json.RawMessage
	if err := readSetting(config.NativeConfDir, whitelistKey, &current); err != nil {
		return nil, err
	}
	_, err := decodeWhitelist(current)
	return current, err
}

func decodeWhitelist(raw json.RawMessage) (whitelist, error) {
	var data whitelist
	if err := json.Unmarshal(raw, &data); err != nil || data.Countries == nil || data.Custom == nil {
		return whitelist{}, fmt.Errorf("invalid native whitelist")
	}
	countries := make([]string, 0, len(data.Countries))
	for _, country := range data.Countries {
		countries = append(countries, strings.ToUpper(country))
	}
	slices.Sort(countries)
	if !slices.Equal(slices.Compact(countries), []string{"CN", "PRIVATE"}) {
		return whitelist{}, fmt.Errorf("native whitelist requires the CN and PRIVATE GeoIP groups")
	}
	return data, nil
}

func SameWhitelist(a, b json.RawMessage) bool {
	// Both values have already been validated. Marshal preserves unknown
	// members, and UseNumber avoids rounding v2rayA-owned numeric values.
	canonical := func(value json.RawMessage) ([]byte, error) {
		var decoded map[string]any
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			return nil, err
		}
		return json.Marshal(decoded)
	}
	first, err := canonical(a)
	if err != nil {
		return false
	}
	second, err := canonical(b)
	return err == nil && bytes.Equal(first, second)
}

func CheckWhitelist(config policy.Config, approved policy.Approved) error {
	current, err := ReadWhitelist(config)
	if err != nil {
		return err
	}
	if !SameWhitelist(current, approved.Whitelist) {
		return fmt.Errorf("native whitelist differs from the approved snapshot")
	}
	return nil
}

// Approval expands the exact whitelist value using the selected GeoIP data.
func Approval(config policy.Config, raw json.RawMessage, path string) (policy.Approved, error) {
	data, err := decodeWhitelist(raw)
	if err != nil {
		return policy.Approved{}, err
	}
	if path == "" {
		path, err = activeGeoIP(config)
		if err != nil {
			return policy.Approved{}, err
		}
	}
	if !filepath.IsAbs(path) {
		return policy.Approved{}, fmt.Errorf("GeoIP path must be absolute")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return policy.Approved{}, err
	}
	file, err := os.ReadFile(path)
	if err != nil {
		return policy.Approved{}, err
	}
	groups, err := decodeGeoIP(file)
	if err != nil {
		return policy.Approved{}, err
	}
	all := append(slices.Clone(groups["CN"]), groups["PRIVATE"]...)
	prefixes, err := policy.Parse(append(all, data.Custom...))
	if err != nil {
		return policy.Approved{}, err
	}
	return config.ValidateApproved(policy.Approved{
		Schema: 1, Created: time.Now().Format(time.RFC3339Nano), NativeMode: "tun",
		Networks: policy.Strings(prefixes), NetworkSHA256: policy.Digest(prefixes),
		Whitelist: raw, GeoIP: path, GeoIPSHA256: fmt.Sprintf("%x", sha256.Sum256(file)),
	})
}

func CheckApproved(config policy.Config, approved policy.Approved) error {
	if err := CheckWhitelist(config, approved); err != nil {
		return err
	}
	return checkGeoIPApproval(config, approved, "")
}

func GeoIPCounts(approved policy.Approved) (map[string]map[string]int, error) {
	data, err := os.ReadFile(approved.GeoIP)
	if err != nil {
		return nil, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != approved.GeoIPSHA256 {
		return nil, fmt.Errorf("native GeoIP changed while reading the whitelist")
	}
	groups, err := decodeGeoIP(data)
	if err != nil {
		return nil, err
	}
	counts := make(map[string]map[string]int, len(groups))
	for code, prefixes := range groups {
		counts[code] = map[string]int{"ipv4": 0, "ipv6": 0}
		for _, prefix := range prefixes {
			family := "ipv4"
			if strings.Contains(prefix, ":") {
				family = "ipv6"
			}
			counts[code][family]++
		}
	}
	return counts, nil
}

func CheckSavedGeoIP(config policy.Config, approved policy.Approved) error {
	if approved.GeoIP == "" {
		return fmt.Errorf("approved snapshot has no GeoIP path")
	}
	return checkGeoIPApproval(config, approved, approved.GeoIP)
}

func checkGeoIPApproval(config policy.Config, approved policy.Approved, path string) error {
	actual, err := Approval(config, approved.Whitelist, path)
	if err != nil {
		return err
	}
	if actual.GeoIPSHA256 != approved.GeoIPSHA256 {
		return fmt.Errorf("native GeoIP file differs from the approved snapshot")
	}
	if actual.NetworkSHA256 != approved.NetworkSHA256 {
		return fmt.Errorf("expanded native whitelist differs from approved destinations")
	}
	return nil
}

func activeGeoIP(config policy.Config) (string, error) {
	parent, err := manager(config)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(proc(parent.PID), "environ"))
	if err != nil {
		return "", err
	}
	for _, entry := range bytes.Split(data, []byte{0}) {
		directory, present := strings.CutPrefix(string(entry), "XRAY_LOCATION_ASSET=")
		if present && filepath.IsAbs(directory) {
			return filepath.Join(directory, "geoip.dat"), nil
		}
	}
	return "/usr/share/v2raya/geoip.dat", nil
}

type protoField struct {
	number uint64
	value  uint64
	bytes  []byte
}

func fields(raw []byte, visit func(protoField) error) error {
	for len(raw) != 0 {
		key, n := binary.Uvarint(raw)
		if n <= 0 || key>>3 == 0 {
			return fmt.Errorf("invalid GeoIP protobuf field")
		}
		raw = raw[n:]
		field := protoField{number: key >> 3}
		switch key & 7 {
		case 0:
			value, n := binary.Uvarint(raw)
			if n <= 0 {
				return fmt.Errorf("invalid GeoIP protobuf varint")
			}
			field.value, raw = value, raw[n:]
		case 1, 2, 5:
			size := uint64(8)
			if key&7 == 2 {
				value, n := binary.Uvarint(raw)
				if n <= 0 {
					return fmt.Errorf("invalid GeoIP protobuf length")
				}
				size, raw = value, raw[n:]
			} else if key&7 == 5 {
				size = 4
			}
			if size > uint64(len(raw)) {
				return fmt.Errorf("truncated GeoIP protobuf field")
			}
			field.bytes, raw = raw[:size], raw[size:]
		default:
			return fmt.Errorf("unsupported GeoIP protobuf field type")
		}
		if err := visit(field); err != nil {
			return err
		}
	}
	return nil
}

func decodeGeoIP(data []byte) (map[string][]string, error) {
	groups := make(map[string][]string)
	err := fields(data, func(group protoField) error {
		if group.number != 1 {
			return nil
		}
		code := ""
		if err := fields(group.bytes, func(field protoField) error {
			if field.number == 1 {
				code = strings.ToUpper(string(field.bytes))
			}
			return nil
		}); err != nil {
			return err
		}
		if code != "CN" && code != "PRIVATE" {
			return nil
		}
		if _, duplicate := groups[code]; duplicate {
			return fmt.Errorf("duplicate GeoIP group %s", code)
		}
		return fields(group.bytes, func(field protoField) error {
			switch field.number {
			case 2:
				prefix, err := decodeCIDR(field.bytes)
				if err != nil {
					return err
				}
				if prefix.IsValid() {
					groups[code] = append(groups[code], prefix.String())
				}
			case 3:
				if field.value != 0 {
					return fmt.Errorf("inverse GeoIP group %s cannot be approved", code)
				}
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if len(groups["CN"]) < 1000 || len(groups["PRIVATE"]) == 0 {
		return nil, fmt.Errorf("GeoIP data must contain CN and PRIVATE bypass groups")
	}
	return groups, nil
}

func decodeCIDR(data []byte) (netip.Prefix, error) {
	var addr netip.Addr
	var bits uint64
	err := fields(data, func(field protoField) error {
		switch field.number {
		case 1:
			value, ok := netip.AddrFromSlice(field.bytes)
			if !ok {
				return fmt.Errorf("invalid GeoIP address length")
			}
			addr = value
		case 2:
			bits = field.value
		}
		return nil
	})
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr == netip.AddrFrom4([4]byte{198, 18, 0, 0}) {
		// v2rayA excludes its FakeIP pool from native GeoIP bypass sets.
		return netip.Prefix{}, nil
	}
	if !addr.IsValid() || bits == 0 || bits > uint64(addr.BitLen()) {
		return netip.Prefix{}, fmt.Errorf("invalid GeoIP prefix length")
	}
	prefix := netip.PrefixFrom(addr, int(bits))
	if prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("noncanonical GeoIP prefix")
	}
	return prefix, nil
}
