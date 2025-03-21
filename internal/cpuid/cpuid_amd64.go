package cpuid

import "github.com/emmansun/gmsm/internal/deps/cpu"

var (
	HasAES = cpu.X86.HasAES
	HasGFMUL = cpu.X86.HasPCLMULQDQ
	HasVPMSUMD = false
)
