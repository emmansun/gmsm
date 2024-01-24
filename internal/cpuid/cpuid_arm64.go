package cpuid

import "golang.org/x/sys/cpu"

var HasAES = cpu.ARM64.HasAES
var HasGFMUL = cpu.ARM64.HasPMULL
