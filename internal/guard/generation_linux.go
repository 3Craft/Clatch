//go:build linux

package guard

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func sameDirectory(first, second string) (bool, error) {
	a, err := os.Stat(first)
	if err != nil {
		return false, err
	}
	b, err := os.Stat(second)
	if err != nil {
		return false, err
	}
	return os.SameFile(a, b), nil
}

func Replace(iface, active, next string) (Replacement, error) {
	same, err := sameDirectory(active, next)
	if err != nil {
		return Replacement{}, err
	}
	if same {
		return Replacement{}, errors.New("replacement requires a separate pin directory")
	}
	index, err := interfaceIndex(iface)
	if err != nil {
		return Replacement{}, err
	}
	current, err := verifyAt(index, active, true)
	if err != nil {
		return Replacement{}, err
	}
	old, err := ebpf.NewProgramFromID(current.ProgramID)
	if err != nil {
		return Replacement{}, err
	}
	defer old.Close()
	fresh, err := ebpf.LoadPinnedProgram(filepath.Join(next, "program"), nil)
	if err != nil {
		return Replacement{}, err
	}
	defer fresh.Close()
	_, beforeSize, err := verifyMaps(old, active, true)
	if err != nil {
		return Replacement{}, err
	}
	newID, afterSize, err := verifyMaps(fresh, next, true)
	if err != nil {
		return Replacement{}, err
	}
	if newID == current.ProgramID {
		return Replacement{}, errors.New("replacement is already the active program")
	}
	oldSettings, _, before, err := readPolicy(active, true)
	if err != nil {
		return Replacement{}, err
	}
	nextSettings, _, after, err := readPolicy(next, true)
	if err != nil {
		return Replacement{}, err
	}
	if !maps.Equal(before, after) || oldSettings.DiagnosticUID != nextSettings.DiagnosticUID ||
		oldSettings.PublicIPv6 != 0 || nextSettings.PublicIPv6 != 0 ||
		nextSettings.TrustedTUNIfindex == uint32(index) {
		return Replacement{}, errors.New("replacement would change the approved policy or diagnostic authority")
	}
	if err := ensureProgramPin(old, current.ProgramID, active); err != nil {
		return Replacement{}, err
	}
	attached, err := link.NewFromID(current.LinkID)
	if err != nil {
		return Replacement{}, err
	}
	defer attached.Close()
	if err := ensureLinkAlias(attached, current.LinkID, next); err != nil {
		return Replacement{}, err
	}
	compareAndSwap, ok := attached.(interface {
		UpdateArgs(link.RawLinkUpdateOptions) error
	})
	if !ok {
		return Replacement{}, errors.New("link lacks atomic compare-and-swap")
	}
	if err := compareAndSwap.UpdateArgs(link.RawLinkUpdateOptions{
		New: fresh, Old: old, Flags: unix.BPF_F_REPLACE,
	}); err != nil {
		return Replacement{}, err
	}
	updated, err := verifyAt(index, next, true)
	if err != nil {
		return Replacement{}, err
	}
	if updated.LinkID != current.LinkID || updated.ProgramID != newID {
		return Replacement{}, errors.New("link or program changed during replacement")
	}
	return Replacement{LinkInfo: updated, OldProgramID: current.ProgramID,
		OldSettingsSize: beforeSize, SettingsSize: afterSize}, nil
}

func ensureProgramPin(prog *ebpf.Program, expected ebpf.ProgramID, dir string) error {
	path := filepath.Join(dir, "program")
	pinned, err := ebpf.LoadPinnedProgram(path, nil)
	if errors.Is(err, os.ErrNotExist) {
		return prog.Pin(path)
	}
	if err != nil {
		return err
	}
	defer pinned.Close()
	id, err := programID(pinned)
	if err != nil {
		return err
	}
	if id != expected {
		return errors.New("existing generation program pin has a different ID")
	}
	return nil
}

func ensureLinkAlias(attached link.Link, expected link.ID, dir string) error {
	path := filepath.Join(dir, "link")
	alias, err := link.LoadPinnedLink(path, nil)
	if errors.Is(err, os.ErrNotExist) {
		return attached.Pin(path)
	}
	if err != nil {
		return err
	}
	defer alias.Close()
	info, err := alias.Info()
	if err != nil {
		return err
	}
	if info.TCX() == nil || info.ID != expected {
		return errors.New("existing generation link pin has a different identity")
	}
	return nil
}

func Prune(iface, active, old string) (map[string]uint32, error) {
	same, err := sameDirectory(active, old)
	if err != nil {
		return nil, err
	}
	if same {
		return nil, errors.New("cannot prune the active generation")
	}
	index, err := interfaceIndex(iface)
	if err != nil {
		return nil, err
	}
	current, err := verifyAt(index, active, true)
	if err != nil {
		return nil, err
	}
	program, err := ebpf.LoadPinnedProgram(filepath.Join(old, "program"), nil)
	if err != nil {
		return nil, err
	}
	defer program.Close()
	id, _, err := verifyMaps(program, old, true)
	if err != nil {
		return nil, err
	}
	alias, err := link.LoadPinnedLink(filepath.Join(old, "link"), nil)
	if err != nil {
		return nil, err
	}
	defer alias.Close()
	previous, err := alias.Info()
	if err != nil {
		return nil, err
	}
	if previous.TCX() == nil || previous.ID != current.LinkID || id == previous.Program {
		return nil, errors.New("generation belongs to another link or is currently active")
	}
	if err := removePins(old, true); err != nil {
		return nil, err
	}
	after, err := verifyAt(index, active, true)
	if err != nil {
		return nil, err
	}
	if after != current {
		return nil, errors.New("active egress program changed during pruning")
	}
	return map[string]uint32{"link_id": uint32(after.LinkID), "program_id": uint32(after.ProgramID),
		"pruned_program_id": uint32(id)}, nil
}

func Detach(iface, dir string) error {
	current, err := Verify(iface, dir)
	if err != nil {
		return err
	}
	attached, err := link.LoadPinnedLink(filepath.Join(dir, "link"), nil)
	if err != nil {
		return err
	}
	defer attached.Close()
	info, err := attached.Info()
	if err != nil {
		return err
	}
	if info.ID != current.LinkID || info.Program != current.ProgramID {
		return fmt.Errorf("egress link changed before detach")
	}
	// Detach also invalidates aliases kept by previously pinned generations.
	if err := attached.Detach(); err != nil {
		return err
	}
	return removePins(dir, true)
}
