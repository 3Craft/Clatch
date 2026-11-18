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

	"clatch-gateway/internal/policy"
)

type whitelist struct {
	Countries []string `json:"countryCodes"`
	Custom    []string `json:"customIps"`
}

func CheckApproved(config policy.Config, approved policy.Approved) error {
	var current, expected whitelist
	if err := readSetting(config.NativeConfDir, whitelistKey, &current); err != nil {
		return err
	}
	if err := json.Unmarshal(approved.Whitelist, &expected); err != nil {
		return fmt.Errorf("invalid approved native whitelist")
	}
	for _, countries := range [][]string{current.Countries, expected.Countries} {
		normalized := make([]string, 0, len(countries))
		for _, country := range countries {
			normalized = append(normalized, strings.ToUpper(country))
		}
		slices.Sort(normalized)
		if !slices.Equal(slices.Compact(normalized), []string{"CN", "PRIVATE"}) {
			return fmt.Errorf("native whitelist requires the CN and PRIVATE GeoIP groups")
		}
	}
	direct, err := policy.Parse(current.Custom)
	if err != nil {
		return err
	}
	prior, err := policy.Parse(expected.Custom)
	if err != nil {
		return err
	}
	if !slices.Equal(direct, prior) {
		return fmt.Errorf("native custom bypass differs from the approved snapshot")
	}
	path, err := activeGeoIP(config)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != approved.GeoIPSHA256 {
		return fmt.Errorf("native GeoIP file differs from the approved snapshot")
	}
	groups, err := decodeGeoIP(data)
	if err != nil {
		return err
	}
	all := append(slices.Clone(groups["CN"]), groups["PRIVATE"]...)
	all = append(all, policy.Strings(direct)...)
	prefixes, err := policy.Parse(all)
	if err != nil {
		return err
	}
	if policy.Digest(prefixes) != approved.NetworkSHA256 {
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
