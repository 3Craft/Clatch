package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode/utf16"
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
	decoder := json.NewDecoder(bytes.NewReader(approved.SourcePolicy))
	decoder.UseNumber()
	if err := decoder.Decode(&expected); err != nil {
		return fmt.Errorf("invalid approved standalone source: %w", err)
	}
	if err := expected.normalize(); err != nil {
		return err
	}
	current, err := ReadSource(c.Proxy.PolicySource)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, expected) || !reflect.DeepEqual(current.Networks, Strings(approved.Prefixes)) {
		return fmt.Errorf("standalone source differs from the approved snapshot")
	}
	return nil
}

func ReadSource(path string) (Source, error) {
	var current Source
	if err := readJSON(path, &current, true); err != nil {
		return Source{}, err
	}
	if err := current.normalize(); err != nil {
		return Source{}, err
	}
	return current, nil
}

func (c Config) ApprovalFor(source Source) (Approved, error) {
	if c.Proxy == nil {
		return Approved{}, fmt.Errorf("a standalone backend is required")
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(map[string]any{
		"metadata": source.Metadata, "networks": source.Networks, "schema": source.Schema,
	}); err != nil {
		return Approved{}, err
	}
	encoded := bytes.TrimSpace(buffer.Bytes())
	prefixes, err := Parse(source.Networks)
	if err != nil {
		return Approved{}, err
	}
	var ascii strings.Builder
	for _, r := range string(encoded) {
		if r >= 127 {
			for _, code := range utf16.Encode([]rune{r}) {
				fmt.Fprintf(&ascii, "\\u%04x", code)
			}
		} else {
			ascii.WriteRune(r)
		}
	}
	digest := sha256.Sum256([]byte(ascii.String()))
	return c.ValidateApproved(Approved{
		Schema: 2, Created: time.Now().Format(time.RFC3339Nano), Networks: source.Networks,
		NetworkSHA256: Digest(prefixes), ProxyKind: c.Proxy.Kind, ProxyMode: c.Proxy.Mode,
		SourcePolicy: encoded, SourceSHA256: fmt.Sprintf("%x", digest),
	})
}
