//go:build (amd64 && !generic)
// +build amd64,!generic

package zuc

import "golang.org/x/sys/cpu"

var supportsGFMUL = cpu.X86.HasPCLMULQDQ || cpu.ARM64.HasPMULL
var useAVX2 = cpu.X86.HasAVX2 && cpu.X86.HasBMI2

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
