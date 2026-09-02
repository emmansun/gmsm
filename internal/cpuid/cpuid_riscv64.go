package cpuid

import "github.com/emmansun/gmsm/internal/deps/cpu"

var (
	HasSM4     = cpu.RISCV64.HasZvksed && (cpu.RISCV64.HasZvbb || cpu.RISCV64.HasZvkb)
	HasAES     = false
	HasGFMUL   = false
	HasGFNI    = false
	HasVPMSUMD = false
)
