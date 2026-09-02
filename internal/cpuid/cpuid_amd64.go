package cpuid

import "github.com/emmansun/gmsm/internal/deps/cpu"

var (
	HasSM4     = false
	HasAES     = cpu.X86.HasAES
	HasGFMUL   = cpu.X86.HasPCLMULQDQ
	HasGFNI    = cpu.X86.HasGFNI
	HasVPMSUMD = false
)
