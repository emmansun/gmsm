//go:build arm64 && (!darwin || ios)

package cpuid

import "github.com/emmansun/gmsm/internal/deps/cpu"

var (
	HasSM4     = cpu.ARM64.HasSM4
	HasAES     = cpu.ARM64.HasAES
	HasGFMUL   = cpu.ARM64.HasPMULL
	HasGFNI    = false
	HasVPMSUMD = false
)
