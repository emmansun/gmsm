//go:build (amd64 || arm64 || ppc64 || ppc64le || (riscv64 && go1.27)) && !purego

package zuc

import (
	"github.com/emmansun/gmsm/internal/cpuid"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

var supportsGFMUL = cpuid.HasGFMUL || cpuid.HasVPMSUMD || cpu.RISCV64.HasZvbc
var supportsZvbb = false //cpu.RISCV64.HasZvbb || cpu.RISCV64.HasZvkb

//go:noescape
func eiaRoundTag4(t *uint32, keyStream *uint32, p *byte)

func block(m *ZUC128Mac, p []byte) {
	if supportsGFMUL {
		for len(p) >= chunk {
			m.genKeywords(m.k0[4:])
			eiaRoundTag4(&m.t, &m.k0[0], &p[0])
			p = p[chunk:]
		}
	} else {
		blockGeneric(m, p)
	}
}
