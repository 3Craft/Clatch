//go:build linux

package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/policy"
)

const BootABIFile = "clatch-rollback-abi.json"

type BootABI struct {
	Object string `json:"object"`
	SHA256 string `json:"sha256"`
}

func BootABIPath(config policy.Config) string {
	return filepath.Join(filepath.Dir(config.ApprovedPolicy), BootABIFile)
}

func (g *Gate) attachBoot(iface string, settings guard.Settings) error {
	entries := g.Config.Entries(g.Approved)
	data, err := os.ReadFile(BootABIPath(g.Config))
	if errors.Is(err, os.ErrNotExist) {
		_, err = guard.Attach(iface, "-", g.Config.Pins, entries, settings)
		return err
	}
	if err != nil {
		return err
	}
	if g.Config.IsTUN() {
		return fmt.Errorf("legacy settings ABI cannot authorize TUN traffic")
	}
	var compatibility BootABI
	if err := json.Unmarshal(data, &compatibility); err != nil {
		return err
	}
	if !filepath.IsAbs(compatibility.Object) || filepath.Clean(compatibility.Object) != compatibility.Object {
		return fmt.Errorf("invalid legacy boot object path")
	}
	object, err := os.ReadFile(compatibility.Object)
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(object)) != compatibility.SHA256 {
		return fmt.Errorf("legacy BPF object differs from the rollback snapshot")
	}
	_, err = guard.AttachLegacy(iface, compatibility.Object, g.Config.Pins, entries, settings)
	return err
}
