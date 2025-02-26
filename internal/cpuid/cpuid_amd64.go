package cpuid

import "golang.org/x/sys/cpu"

var (
	HasAES = cpu.X86.HasAES
	HasGFMUL = cpu.X86.HasPCLMULQDQ
	HasVPMSUMD = false
)
