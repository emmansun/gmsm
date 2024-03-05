//go:build (amd64 || arm64) && !purego

package zuc

import (
	"github.com/emmansun/gmsm/internal/cpuid"
	"golang.org/x/sys/cpu"
)

var supportsAES = cpuid.HasAES
var supportsGFMUL = cpuid.HasGFMUL
var useAVX = cpu.X86.HasAVX

//go:noescape
func eia3Round16B(t *uint32, keyStream *uint32, p *byte, tagSize int)

func block(m *ZUC128Mac, p []byte) {
	if supportsGFMUL {
		for len(p) >= chunk {
			m.genKeywords(m.k0[4:])
			eia3Round16B(&m.t, &m.k0[0], &p[0], m.tagSize)
			p = p[chunk:]
		}
	} else {
		blockGeneric(m, p)
	}
}
