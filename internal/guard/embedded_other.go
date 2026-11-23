//go:build !linux

package guard

// EmbeddedBPF reports whether an embedded eBPF object is available on this platform.
func EmbeddedBPF() bool {
	return false
}
