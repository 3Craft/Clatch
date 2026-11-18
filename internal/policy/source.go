package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
)

type Source struct {
	Schema   int            `json:"schema"`
	Networks []string       `json:"networks"`
	Metadata map[string]any `json:"metadata"`
}

func (source *Source) normalize() error {
	prefixes, err := Parse(source.Networks)
	if err != nil {
		return err
	}
	if source.Schema != 1 || Elements(prefixes, 32) == "" {
		return fmt.Errorf("standalone source requires a schema-1 IPv4 policy")
	}
	source.Networks = Strings(prefixes)
	if source.Metadata == nil {
		source.Metadata = map[string]any{}
	}
	return nil
}

func (c Config) CheckSource(approved Approved) error {
	if c.Proxy == nil {
		return fmt.Errorf("standalone policy source is unavailable")
	}
	if len(approved.Transition) != 0 && !bytes.Equal(bytes.TrimSpace(approved.Transition), []byte("null")) {
		return fmt.Errorf("unfinished approval transition needs recovery")
	}
	var expected Source
	if err := json.Unmarshal(approved.SourcePolicy, &expected); err != nil {
		return fmt.Errorf("invalid approved standalone source: %w", err)
	}
	if err := expected.normalize(); err != nil {
		return err
	}
	var current Source
	if err := readJSON(c.Proxy.PolicySource, &current, true); err != nil {
		return err
	}
	if err := current.normalize(); err != nil {
		return err
	}
	if !reflect.DeepEqual(current, expected) || !reflect.DeepEqual(current.Networks, Strings(approved.Prefixes)) {
		return fmt.Errorf("standalone source differs from the approved snapshot")
	}
	return nil
}
