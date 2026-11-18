//go:build linux

package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"clatch-gateway/internal/firewall"
	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/native"
	"clatch-gateway/internal/system"
)

type nativeJournal struct {
	Schema          int             `json:"schema"`
	BootID          string          `json:"boot_id"`
	Previous        string          `json:"previous"`
	Next            string          `json:"next"`
	Candidate       native.Snapshot `json:"candidate"`
	PreviousProgram uint32          `json:"previous_program_id"`
	Program         uint32          `json:"program_id"`
	Link            uint32          `json:"link_id"`
	NetworkSHA      string          `json:"network_sha256"`
}

func NativeBind(path string, bind bool) (map[string]any, error) {
	return nativeLifecycle(path, "", bind, false)
}

func NativeHook(path, confdir, stage string) (map[string]any, error) {
	switch stage {
	case "post-start":
		return nativeLifecycle(path, confdir, true, true)
	case "pre-start", "pre-stop", "post-stop":
		return nativeLifecycle(path, confdir, false, true)
	default:
		return nil, fmt.Errorf("invalid native lifecycle stage")
	}
}

func nativeLifecycle(path, confdir string, bind, hook bool) (map[string]any, error) {

	var result map[string]any
	err := WithLock(func() error {
		gate, err := open(path)
		if err != nil {
			return err
		}
		if !gate.Config.NativeTUN {
			return fmt.Errorf("native lifecycle requires v2rayA native TUN configuration")
		}
		if confdir != "" && gate.Config.NativeConfDir != confdir {
			return fmt.Errorf("hook configuration directory differs from the approved profile")
		}
		if err := gate.recoverNative(); err != nil {
			return err
		}
		var candidate native.Snapshot
		if bind {
			if err := validateNativeHookSource(gate); err != nil {
				return err
			}
			candidate, err = native.Inspect(gate.Config)
			if err != nil {
				return err
			}
		}
		if hook && bind {
			if err := native.InstallCapture(gate.Config, gate.Approved); err != nil {
				return err
			}
		}
		if err := gate.switchNative(candidate); err != nil {
			return err
		}
		if hook && !bind {
			if err := native.RemoveCapture(); err != nil {
				return err
			}
		}
		result, err = gate.Verify()
		if err != nil && bind {
			return errors.Join(err, gate.switchNative(native.Snapshot{}))
		}
		return err
	})
	return result, err
}

func (g *Gate) journalPath() string {
	return filepath.Join(filepath.Dir(g.Config.ApprovedPolicy), "pending-native-tun-generation.json")
}

func putJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return system.WriteAtomic(path, append(raw, '\n'), 0600)
}

func bootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(raw)), err
}

func (g *Gate) installNativeRules(index uint32) error {
	rules, err := firewall.RenderGuard(g.Config, g.Approved, index)
	if err != nil {
		return err
	}
	return firewall.Apply(rules, g.Config.RulesFile, g.fingerprintPath())
}

func (g *Gate) switchNative(candidate native.Snapshot) error {
	current, err := guard.Verify(g.Config.Interface, g.Config.Pins)
	if err != nil {
		return err
	}
	active, err := guard.Dump(g.Config.Pins)
	if err != nil {
		return err
	}
	settings := guard.Settings{DiagnosticUID: g.Config.DiagnosticUID, TrustedTUNIfindex: active.TrustedTUNIfindex}
	policyEntries := g.Config.Entries(g.Approved)
	if _, err := guard.CheckPolicy(g.Config.Pins, policyEntries, settings); err != nil {
		return err
	}
	if active.TrustedTUNIfindex == candidate.Ifindex {
		if err := g.installNativeRules(candidate.Ifindex); err != nil {
			return err
		}
		return native.Publish(candidate)
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	previous := g.Config.Pins
	next := filepath.Join(filepath.Dir(previous), fmt.Sprintf("jdn-v2raya-tun-%d", time.Now().UnixNano()))
	settings.TrustedTUNIfindex = candidate.Ifindex
	prepared, err := guard.Prepare("-", next, policyEntries, settings)
	if err != nil {
		return err
	}
	if candidate.Ifindex != 0 {
		if verified, err := native.Inspect(g.Config); err != nil || verified != candidate {
			return errors.Join(fmt.Errorf("native TUN changed before binding"), discardPrepared(next))
		}
	}
	if err := g.installNativeRules(candidate.Ifindex); err != nil {
		return errors.Join(err, discardPrepared(next))
	}
	journal := nativeJournal{
		Schema: 1, BootID: boot, Previous: previous, Next: next, Candidate: candidate,
		PreviousProgram: uint32(current.ProgramID), Program: uint32(prepared.ProgramID),
		Link: uint32(current.LinkID), NetworkSHA: g.Approved.NetworkSHA256,
	}
	if err := putJSON(g.journalPath(), journal); err != nil {
		return errors.Join(err, g.installNativeRules(0), discardPrepared(next))
	}
	// A successful link update can outlive an error or an interrupted process.
	_, replaceErr := guard.Replace(g.Config.Interface, previous, next)
	if err := g.recoverNative(); err != nil {
		return errors.Join(replaceErr, err)
	}
	if g.Config.Pins != next {
		var cleanup error
		if _, err := os.Lstat(filepath.Join(next, "link")); err == nil {
			_, cleanup = guard.Prune(g.Config.Interface, g.Config.Pins, next)
		} else if errors.Is(err, os.ErrNotExist) {
			cleanup = discardPrepared(next)
		} else {
			cleanup = err
		}
		if replaceErr == nil {
			replaceErr = fmt.Errorf("selected TCX generation differs from the requested update")
		}
		return errors.Join(replaceErr, cleanup)
	}
	return g.collectNative(previous)
}

func discardPrepared(path string) error {
	for _, name := range []string{"program", "policy_sets", "settings", "counters"} {
		if err := os.Remove(filepath.Join(path, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(path)
}

func (g *Gate) recoverNative() error {
	journalPath := g.journalPath()
	raw, err := os.ReadFile(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal nativeJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		return err
	}
	valid := journal.Schema == 1 && journal.NetworkSHA == g.Approved.NetworkSHA256 &&
		journal.Next != journal.Previous && journal.Program > 0 && journal.PreviousProgram > 0 && journal.Link > 0
	pinRoot := filepath.Dir(g.Config.Pins)
	for _, path := range []string{journal.Previous, journal.Next} {
		valid = valid && filepath.Clean(path) == path && filepath.Dir(path) == pinRoot
	}
	if !valid || g.Config.Pins != journal.Previous && g.Config.Pins != journal.Next {
		return fmt.Errorf("unrecognized native generation journal")
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	if journal.BootID != boot {
		if err := native.Publish(native.Snapshot{}); err != nil {
			return err
		}
		return os.Remove(journalPath)
	}

	selected, candidate := "", native.Snapshot{}
	for _, choice := range []struct {
		path    string
		program uint32
	}{
		{journal.Next, journal.Program}, {journal.Previous, journal.PreviousProgram},
	} {
		info, err := guard.Verify(g.Config.Interface, choice.path)
		if err == nil && uint32(info.LinkID) == journal.Link && uint32(info.ProgramID) == choice.program {
			selected = choice.path
			break
		}
	}
	if selected == "" {
		return fmt.Errorf("cannot identify active native TCX generation")
	}
	if selected == journal.Next {
		candidate = journal.Candidate
		if candidate.Ifindex != 0 {
			if actual, err := native.Inspect(g.Config); err != nil || actual != candidate {
				candidate = native.Snapshot{}
			}
		}
	} else if existing, err := native.Identity(g.Config); err == nil {
		candidate = existing
	}
	if selected != g.Config.Pins {
		raw, err := os.ReadFile(g.Path)
		if err != nil {
			return err
		}
		var config map[string]json.RawMessage
		if err := json.Unmarshal(raw, &config); err != nil {
			return err
		}
		value, err := json.Marshal(selected)
		if err != nil {
			return err
		}
		config["pins"] = value
		if err := putJSON(g.Path, config); err != nil {
			return err
		}
		g.Config.Pins = selected
	}
	if err := g.installNativeRules(candidate.Ifindex); err != nil {
		return err
	}
	if err := native.Publish(candidate); err != nil {
		return err
	}
	return os.Remove(journalPath)
}

func (g *Gate) collectNative(previous string) error {
	path := filepath.Join(filepath.Dir(g.Config.ApprovedPolicy), "native-tun-generations.json")
	record := struct {
		Schema      int      `json:"schema"`
		Original    string   `json:"original"`
		Generations []string `json:"generations"`
	}{Schema: 1, Original: previous}
	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, &record); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if record.Schema != 1 || filepath.Dir(record.Original) != filepath.Dir(g.Config.Pins) {
		return fmt.Errorf("unrecognized native generation ownership")
	}
	kept := []string{previous, g.Config.Pins}
	for _, old := range record.Generations {
		if slices.Contains(kept, old) {
			continue
		}
		if old == record.Original {
			kept = append(kept, old)
			continue
		}
		if filepath.Clean(old) != old || filepath.Dir(old) != filepath.Dir(g.Config.Pins) {
			return fmt.Errorf("invalid native generation path")
		}
		if _, err := os.Stat(old); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if _, err := guard.Prune(g.Config.Interface, g.Config.Pins, old); err != nil {
			return err
		}
	}
	record.Generations = kept
	return putJSON(path, record)
}

func validateNativeHookSource(gate *Gate) error {
	tx, exists, err := savedTransaction(gate.Config, gate.Path)
	if err != nil {
		return err
	}
	if !exists {
		return native.CheckApproved(gate.Config, gate.Approved)
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	if tx.BootID != boot || tx.State != "staged" ||
		gate.Approved.NetworkSHA256 != tx.Restricted.NetworkSHA256 {
		return fmt.Errorf("recover native policy transaction before starting the core")
	}
	if native.CheckApproved(gate.Config, tx.Desired) != nil &&
		native.CheckApproved(gate.Config, tx.Old) != nil {
		return fmt.Errorf("native settings match neither side of the approved policy transaction")
	}
	return nil
}
