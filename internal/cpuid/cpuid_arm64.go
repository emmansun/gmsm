//go:build arm64 && (!darwin || ios)

package cpuid

import "golang.org/x/sys/cpu"

var (
	HasAES = cpu.ARM64.HasAES
	HasGFMUL = cpu.ARM64.HasPMULL
	HasVPMSUMD = false
)
