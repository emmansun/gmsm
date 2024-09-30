package cpuid

import "golang.org/x/sys/cpu"

var HasAES = cpu.X86.HasAES
var HasGFMUL = cpu.X86.HasPCLMULQDQ
var HasVPMSUMD = false
