//go:build linux

package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"clatch-gateway/internal/system"
)

func Apply(rules, rulesPath, fingerprintPath string) error {
	if _, err := system.Command(rules, "nft", "--check", "-f", "-"); err != nil {
		return err
	}
	if _, err := system.Command(rules, "nft", "-f", "-"); err != nil {
		return err
	}
	fingerprint, err := currentFingerprint()
	if err != nil {
		return err
	}
	if rulesPath != "" {
		if err := system.WriteAtomic(rulesPath, []byte(rules), 0600); err != nil {
			return err
		}
	}
	return system.WriteAtomic(fingerprintPath, []byte(digestRules(rules)+" "+fingerprint+"\n"), 0600)
}

func Verify(rules, fingerprintPath string) error {
	want, err := os.ReadFile(fingerprintPath)
	if err != nil {
		return err
	}
	got, err := currentFingerprint()
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(want)) != digestRules(rules)+" "+got {
		return fmt.Errorf("active nft guard differs from the last verified rule set")
	}
	return nil
}

func digestRules(rules string) string {
	digest := sha256.Sum256([]byte(rules))
	return hex.EncodeToString(digest[:])
}

func currentFingerprint() (string, error) {
	data, err := system.Command("", "nft", "-s", "-j", "list", "table", "inet", tableName)
	if err != nil {
		return "", err
	}
	var result struct {
		Objects []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", err
	}
	objects := make([]map[string]any, 0, len(result.Objects))
	for _, obj := range result.Objects {
		if _, isMeta := obj["metainfo"]; isMeta {
			continue
		}
		for _, item := range obj {
			if attributes, ok := item.(map[string]any); ok {
				delete(attributes, "handle")
			}
		}
		objects = append(objects, obj)
	}
	if len(objects) < 2 {
		return "", fmt.Errorf("nft did not return the guard table and contents")
	}
	normalized, err := json.Marshal(objects)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(normalized)
	return hex.EncodeToString(digest[:]), nil
}
