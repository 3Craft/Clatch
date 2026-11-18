//go:build linux && embedded_bpf

package guard

import _ "embed"

//go:embed gateway_bpfel.o
var embeddedObject []byte
