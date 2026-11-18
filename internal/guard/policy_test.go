package guard

import (
	"strings"
	"testing"
	"unsafe"
)

func TestPolicyKeyABI(t *testing.T) {
	if size := unsafe.Sizeof(Key{}); size != 24 {
		t.Fatalf("key has %d bytes instead of 24", size)
	}
	policy, err := ParsePolicy(strings.NewReader("4 192.168.1.0/24 3\n4 192.168.1.96/32 11\n4 198.18.0.42/32 16\n6 fc00::/7 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	key := Key{PrefixLen: 56, Family: 4, Address: [16]byte{192, 168, 1}}
	if policy[key] != Direct|LAN {
		t.Fatalf("missing ABI key %+v", key)
	}
}

func TestPolicyRejectsUnsafeEntries(t *testing.T) {
	for _, input := range []string{
		"",
		"4 0.0.0.0/0 1\n",
		"4 192.168.1.1/24 1\n",
		"4 192.168.1.0/24 4\n",
		"4 192.168.1.96/32 11\n",
		"4 192.168.1.0/24 3\n4 192.168.1.0/24 1\n",
		"6 192.168.1.0/24 3\n",
	} {
		if _, err := ParsePolicy(strings.NewReader(input)); err == nil {
			t.Errorf("unsafe policy accepted: %q", input)
		}
	}
}
