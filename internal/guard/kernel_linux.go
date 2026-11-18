//go:build linux

package guard

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	programName = "gateway_egress"
	wanProgram  = "wan_egress"
)

var mapNames = [...]string{"policy_sets", "settings", "counters"}

type Settings struct {
	DiagnosticUID     uint32 `json:"diagnostic_uid"`
	PublicIPv6        uint32 `json:"public_ipv6"`
	TrustedTUNIfindex uint32 `json:"trusted_tun_ifindex"`
}

type LinkInfo struct {
	Ifindex   uint32         `json:"ifindex"`
	LinkID    link.ID        `json:"link_id"`
	ProgramID ebpf.ProgramID `json:"program_id"`
}

type Prepared struct {
	ProgramID         ebpf.ProgramID `json:"program_id"`
	SettingsSize      uint32         `json:"settings_size"`
	TrustedTUNIfindex uint32         `json:"trusted_tun_ifindex"`
}

type Replacement struct {
	LinkInfo
	OldProgramID    ebpf.ProgramID `json:"old_program_id"`
	OldSettingsSize uint32         `json:"old_settings_size"`
	SettingsSize    uint32         `json:"settings_size"`
}

type ActivePolicy struct {
	Settings
	MapID   ebpf.MapID `json:"map_id"`
	Entries [][3]any   `json:"entries"`
}

func loadCollection(path, name string) (*ebpf.Collection, error) {
	var spec *ebpf.CollectionSpec
	var err error
	if path == "-" {
		if len(embeddedObject) == 0 {
			return nil, errors.New("build with embedded_bpf or supply an eBPF object path")
		}
		spec, err = ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedObject))
	} else {
		spec, err = ebpf.LoadCollectionSpec(path)
	}
	if err != nil {
		return nil, err
	}
	if program := spec.Programs[name]; program == nil ||
		program.Type != ebpf.SchedCLS || program.AttachType != ebpf.AttachTCXEgress {
		return nil, errors.New("object has no compatible TCX egress program")
	}
	for _, mapName := range mapNames {
		if spec.Maps[mapName] == nil {
			return nil, fmt.Errorf("object lacks map %s", mapName)
		}
	}
	// Load only the program selected for this attachment.
	for symbol := range spec.Programs {
		if symbol != name {
			delete(spec.Programs, symbol)
		}
	}
	return ebpf.NewCollection(spec)
}

func validateSettings(settings Settings) error {
	if settings.DiagnosticUID == 0 || settings.DiagnosticUID == 65534 ||
		settings.DiagnosticUID == ^uint32(0) || settings.PublicIPv6 != 0 {
		return errors.New("unsafe egress guard settings")
	}
	data, err := os.ReadFile("/proc/sys/kernel/overflowuid")
	if err != nil {
		return err
	}
	var overflow uint32
	if _, err := fmt.Sscan(string(data), &overflow); err != nil {
		return err
	}
	if settings.DiagnosticUID == overflow {
		return errors.New("overflow UID cannot be diagnostic")
	}
	return nil
}

func newPolicy(entries Policy) (*ebpf.Map, error) {
	if err := entries.validate(); err != nil {
		return nil, err
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "clatch_policy", Type: ebpf.LPMTrie, KeySize: 24,
		ValueSize: 4, MaxEntries: maxEntries, Flags: unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		return nil, err
	}
	for key, value := range entries {
		if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
			m.Close()
			return nil, fmt.Errorf("populate egress policy: %w", err)
		}
	}
	return m, nil
}

func createGeneration(object, dir string, entries Policy, settings Settings, allowLegacy bool, program string) (*ebpf.Collection, error) {
	if err := validateSettings(settings); err != nil {
		return nil, err
	}
	if filepath.Clean(dir) != dir || !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("pin directory must be a canonical absolute path: %s", dir)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(filepath.Dir(dir), &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.BPF_FS_MAGIC {
		return nil, fmt.Errorf("pin directory parent is outside bpffs: %s", dir)
	}
	inner, err := newPolicy(entries)
	if err != nil {
		return nil, err
	}
	defer inner.Close()
	collection, err := loadCollection(object, program)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			collection.Close()
		}
	}()

	zero := uint32(0)
	if err := collection.Maps["policy_sets"].Update(&zero, inner, ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("install initial policy: %w", err)
	}
	config := collection.Maps["settings"]
	var value any = &settings
	legacy := config.ValueSize() == 8
	switch {
	case legacy && allowLegacy && settings.TrustedTUNIfindex == 0:
		value = &[2]uint32{settings.DiagnosticUID, settings.PublicIPv6}
	case config.ValueSize() == 12 && !allowLegacy:
	default:
		return nil, fmt.Errorf("BPF settings ABI differs from the selected attachment mode")
	}
	if err := config.Update(&zero, value, ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("initialize guard settings: %w", err)
	}
	if err := config.Freeze(); err != nil {
		return nil, fmt.Errorf("freeze guard settings: %w", err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, fmt.Errorf("create pin directory: %w", err)
	}
	defer func() {
		if failed {
			_ = removePins(dir, false)
		}
	}()
	for _, name := range mapNames {
		if err := collection.Maps[name].Pin(filepath.Join(dir, name)); err != nil {
			return nil, err
		}
	}
	if err := collection.Programs[program].Pin(filepath.Join(dir, "program")); err != nil {
		return nil, err
	}
	if _, _, err := verifyProgramMaps(collection.Programs[program], dir, legacy, program); err != nil {
		return nil, err
	}
	failed = false
	return collection, nil
}

func Prepare(object, dir string, policy Policy, settings Settings) (Prepared, error) {
	collection, err := createGeneration(object, dir, policy, settings, false, programName)
	if err != nil {
		return Prepared{}, err
	}
	defer collection.Close()
	id, err := programID(collection.Programs[programName])
	if err != nil {
		_ = removePins(dir, false)
		return Prepared{}, err
	}
	return Prepared{ProgramID: id, SettingsSize: 12, TrustedTUNIfindex: settings.TrustedTUNIfindex}, nil
}

func interfaceIndex(iface string) (int, error) {
	device, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, err
	}
	return device.Index, nil
}

func query(index int) (*link.QueryResult, error) {
	return link.QueryPrograms(link.QueryOptions{Target: index, Attach: ebpf.AttachTCXEgress})
}

func Attach(iface, object, dir string, policy Policy, settings Settings) (LinkInfo, error) {
	return attach(iface, object, dir, policy, settings, false, programName)
}

func RequireUnusedEgress(iface string) error {
	index, err := interfaceIndex(iface)
	if err != nil {
		return err
	}
	programs, err := query(index)
	if err != nil {
		return err
	}
	if len(programs.Programs) != 0 {
		return fmt.Errorf("interface %s already has TCX egress programs", iface)
	}
	return nil
}

// AttachLegacy keeps the previous non-TUN settings ABI available for rollback.
func AttachLegacy(iface, object, dir string, policy Policy, settings Settings) (LinkInfo, error) {
	return attach(iface, object, dir, policy, settings, true, programName)
}

func AttachWAN(iface, object, dir string, policy Policy, settings Settings) (LinkInfo, error) {
	return attach(iface, object, dir, policy, settings, false, wanProgram)
}

func attach(iface, object, dir string, policy Policy, settings Settings, legacy bool, program string) (LinkInfo, error) {
	index, err := interfaceIndex(iface)
	if err != nil {
		return LinkInfo{}, err
	}
	if settings.TrustedTUNIfindex == uint32(index) {
		return LinkInfo{}, errors.New("egress interface cannot be the trusted TUN")
	}
	chain, err := query(index)
	if err != nil {
		return LinkInfo{}, err
	}
	if len(chain.Programs) != 0 || chain.Revision == 0 {
		return LinkInfo{}, errors.New("TCX egress is occupied or lacks revision support")
	}
	collection, err := createGeneration(object, dir, policy, settings, legacy, program)
	if err != nil {
		return LinkInfo{}, err
	}
	defer collection.Close()
	ok := false
	defer func() {
		if !ok {
			_ = removePins(dir, true)
		}
	}()

	attached, err := link.AttachTCX(link.TCXOptions{
		Interface: index, Program: collection.Programs[program], Attach: ebpf.AttachTCXEgress,
		Anchor: link.Head(), ExpectedRevision: chain.Revision,
	})
	if err != nil {
		return LinkInfo{}, err
	}
	defer attached.Close()
	if err := attached.Pin(filepath.Join(dir, "link")); err != nil {
		return LinkInfo{}, err
	}
	info, err := verifyProgramAt(index, dir, legacy, program)
	ok = err == nil
	return info, err
}

func programID(prog *ebpf.Program) (ebpf.ProgramID, error) {
	info, err := prog.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		return 0, errors.New("kernel did not return a program ID")
	}
	return id, nil
}

func verifyMaps(prog *ebpf.Program, dir string, legacy bool) (ebpf.ProgramID, uint32, error) {
	return verifyProgramMaps(prog, dir, legacy, programName)
}

func verifyProgramMaps(prog *ebpf.Program, dir string, legacy bool, name string) (ebpf.ProgramID, uint32, error) {
	info, err := prog.Info()
	if err != nil {
		return 0, 0, err
	}
	ids, available := info.MapIDs()
	id, identified := info.ID()
	if !available || len(ids) != len(mapNames) || !identified || info.Type != ebpf.SchedCLS || info.Name != name {
		return 0, 0, errors.New("unexpected egress program type, name or map count")
	}
	types := [...]ebpf.MapType{ebpf.ArrayOfMaps, ebpf.Array, ebpf.PerCPUArray}
	values := [...]uint32{4, 12, 8}
	counts := [...]uint32{1, 1, uint32(len(counterNames))}
	var settingsSize uint32
	for i, name := range mapNames {
		m, err := openMap(dir, name)
		if err != nil {
			return 0, 0, err
		}
		props, err := m.Info()
		m.Close()
		if err != nil {
			return 0, 0, err
		}
		mapID, present := props.ID()
		sameSize := props.ValueSize == values[i] || legacy && name == "settings" && props.ValueSize == 8
		if !present || !containsMap(ids, mapID) || props.Type != types[i] ||
			props.KeySize != 4 || !sameSize || props.MaxEntries != counts[i] {
			return 0, 0, fmt.Errorf("pinned map %s differs from the egress program", name)
		}
		if name == "settings" {
			settingsSize = props.ValueSize
		}
	}
	return id, settingsSize, nil
}

func containsMap(ids []ebpf.MapID, expected ebpf.MapID) bool {
	for _, id := range ids {
		if id == expected {
			return true
		}
	}
	return false
}

func openMap(dir, name string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(filepath.Join(dir, name), nil)
}

func verifyAt(index int, dir string, legacy bool) (LinkInfo, error) {
	return verifyProgramAt(index, dir, legacy, programName)
}

func verifyProgramAt(index int, dir string, legacy bool, program string) (LinkInfo, error) {
	attached, err := link.LoadPinnedLink(filepath.Join(dir, "link"), nil)
	if err != nil {
		return LinkInfo{}, err
	}
	defer attached.Close()
	info, err := attached.Info()
	if err != nil {
		return LinkInfo{}, err
	}
	tc := info.TCX()
	if tc == nil || tc.Ifindex != uint32(index) || uint32(tc.AttachType) != uint32(ebpf.AttachTCXEgress) {
		return LinkInfo{}, errors.New("pinned link does not protect the requested egress interface")
	}
	chain, err := query(index)
	if err != nil {
		return LinkInfo{}, err
	}
	if len(chain.Programs) != 1 {
		return LinkInfo{}, errors.New("the egress chain does not contain exactly one program")
	}
	id, ok := chain.Programs[0].LinkID()
	if !ok || id != info.ID || chain.Programs[0].ID != info.Program {
		return LinkInfo{}, errors.New("pinned TCX link does not match the active chain")
	}
	prog, err := ebpf.NewProgramFromID(info.Program)
	if err != nil {
		return LinkInfo{}, err
	}
	defer prog.Close()
	if _, _, err := verifyProgramMaps(prog, dir, legacy, program); err != nil {
		return LinkInfo{}, err
	}
	return LinkInfo{Ifindex: tc.Ifindex, LinkID: info.ID, ProgramID: info.Program}, nil
}

func Verify(iface, dir string) (LinkInfo, error) {
	index, err := interfaceIndex(iface)
	if err != nil {
		return LinkInfo{}, err
	}
	return verifyAt(index, dir, false)
}

// VerifyStandalone accepts the pre-TUN settings ABI on standalone gateways.
func VerifyStandalone(iface, dir string) (LinkInfo, error) {
	index, err := interfaceIndex(iface)
	if err != nil {
		return LinkInfo{}, err
	}
	return verifyAt(index, dir, true)
}

func removePins(dir string, removeLink bool) error {
	names := []string{"program", "policy_sets", "settings", "counters"}
	if removeLink {
		names = append(names, "link")
	}
	var errs []error
	for _, name := range names {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func VerifyWAN(iface, dir string) (LinkInfo, error) {
	index, err := interfaceIndex(iface)
	if err != nil {
		return LinkInfo{}, err
	}
	return verifyProgramAt(index, dir, false, wanProgram)
}
