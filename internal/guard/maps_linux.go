//go:build linux

package guard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"sort"

	"github.com/cilium/ebpf"
)

var counterNames = [...]string{
	"allow_direct", "allow_return", "allow_diagnostic", "allow_arp", "allow_ndp",
	"deny_destination", "deny_return", "deny_parse", "deny_ipv6", "deny_policy",
}

func readPolicy(dir string, legacy bool) (Settings, ebpf.MapID, Policy, error) {
	outer, err := openMap(dir, "policy_sets")
	if err != nil {
		return Settings{}, 0, nil, err
	}
	defer outer.Close()
	config, err := openMap(dir, "settings")
	if err != nil {
		return Settings{}, 0, nil, err
	}
	defer config.Close()

	size := config.ValueSize()
	if size != 12 && !(legacy && size == 8) {
		return Settings{}, 0, nil, fmt.Errorf("unexpected settings size %d", size)
	}
	zero := uint32(0)
	raw, err := config.LookupBytes(zero)
	if err != nil {
		return Settings{}, 0, nil, err
	}
	if uint32(len(raw)) != size {
		return Settings{}, 0, nil, errors.New("missing guard settings")
	}
	settings := Settings{
		DiagnosticUID: binary.NativeEndian.Uint32(raw),
		PublicIPv6:    binary.NativeEndian.Uint32(raw[4:]),
	}
	if size == 12 {
		settings.TrustedTUNIfindex = binary.NativeEndian.Uint32(raw[8:])
	}
	var id ebpf.MapID
	if err := outer.Lookup(zero, &id); err != nil {
		return Settings{}, 0, nil, err
	}
	inner, err := ebpf.NewMapFromID(id)
	if err != nil {
		return Settings{}, 0, nil, err
	}
	defer inner.Close()
	if inner.Type() != ebpf.LPMTrie || inner.KeySize() != 24 ||
		inner.ValueSize() != 4 || inner.MaxEntries() != maxEntries {
		return Settings{}, 0, nil, errors.New("active policy map has an incompatible ABI")
	}
	entries := make(Policy)
	it := inner.Iterate()
	var key Key
	var value uint32
	for it.Next(&key, &value) {
		entries[key] = value
	}
	if err := it.Err(); err != nil {
		return Settings{}, 0, nil, err
	}
	if err := entries.validate(); err != nil {
		return Settings{}, 0, nil, fmt.Errorf("invalid active policy: %w", err)
	}
	return settings, id, entries, nil
}

func Dump(dir string) (ActivePolicy, error) {
	settings, id, policy, err := readPolicy(dir, false)
	if err != nil {
		return ActivePolicy{}, err
	}
	rows := make([][3]any, 0, len(policy))
	for key, flags := range policy {
		prefix, err := key.Prefix()
		if err != nil {
			return ActivePolicy{}, err
		}
		rows = append(rows, [3]any{key.Family, prefix.String(), flags})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i][0] != rows[j][0] {
			return rows[i][0].(uint32) < rows[j][0].(uint32)
		}
		return rows[i][1].(string) < rows[j][1].(string)
	})
	return ActivePolicy{Settings: settings, MapID: id, Entries: rows}, nil
}

func UpdatePolicy(dir string, policy Policy) error {
	outer, err := openMap(dir, "policy_sets")
	if err != nil {
		return err
	}
	defer outer.Close()
	if outer.Type() != ebpf.ArrayOfMaps || outer.KeySize() != 4 ||
		outer.ValueSize() != 4 || outer.MaxEntries() != 1 {
		return errors.New("invalid policy map selector")
	}
	fresh, err := newPolicy(policy)
	if err != nil {
		return err
	}
	defer fresh.Close()
	// Prepare the entire trie before changing the sole active reference.
	return outer.Update(uint32(0), fresh, ebpf.UpdateAny)
}

func Stats(dir string) (map[string]uint64, error) {
	counter, err := openMap(dir, "counters")
	if err != nil {
		return nil, err
	}
	defer counter.Close()
	if counter.Type() != ebpf.PerCPUArray || counter.KeySize() != 4 ||
		counter.ValueSize() != 8 || counter.MaxEntries() != uint32(len(counterNames)) {
		return nil, errors.New("invalid guard counters map")
	}
	totals := make(map[string]uint64, len(counterNames))
	for i, name := range counterNames {
		var values []uint64
		if err := counter.Lookup(uint32(i), &values); err != nil {
			return nil, err
		}
		var total uint64
		for _, value := range values {
			total += value
		}
		totals[name] = total
	}
	return totals, nil
}

// CheckPolicy compares the active kernel trie and frozen settings with approved values.
func CheckPolicy(dir string, expected Policy, settings Settings) (ebpf.MapID, error) {
	active, id, current, err := readPolicy(dir, settings.TrustedTUNIfindex == 0)
	if err != nil {
		return 0, err
	}
	if active != settings || !maps.Equal(current, expected) {
		return 0, errors.New("active TCX policy or settings differ from the approved configuration")
	}
	return id, nil
}

// EmbeddedBPF reports whether the release BPF object is embedded in this binary.
func EmbeddedBPF() bool {
	return len(embeddedObject) > 0
}

// SettingsABI is used after live verification to preserve the rollback ABI.
func SettingsABI(pins string) (uint32, error) {
	settings, err := openMap(pins, "settings")
	if err != nil {
		return 0, err
	}
	defer settings.Close()
	size := settings.ValueSize()
	if size != 8 && size != 12 {
		return 0, fmt.Errorf("unsupported guard settings size %d", size)
	}
	return size, nil
}
