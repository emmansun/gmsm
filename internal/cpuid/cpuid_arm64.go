//go:build arm64 && (!darwin || ios)

package cpuid

import "github.com/emmansun/gmsm/internal/deps/cpu"

var (
	HasAES = cpu.ARM64.HasAES
	HasGFMUL = cpu.ARM64.HasPMULL
	HasVPMSUMD = false
)
