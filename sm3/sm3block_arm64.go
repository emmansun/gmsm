//go:build arm64
// +build arm64

package sm3

import "golang.org/x/sys/cpu"

var useSM3NI = cpu.ARM64.HasSM3
