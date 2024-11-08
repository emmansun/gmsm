//go:build (amd64 || arm64 || ppc64 || ppc64le) && !purego

package zuc

import (
	"github.com/emmansun/gmsm/internal/cpuid"
)

var supportsGFMUL = cpuid.HasGFMUL || cpuid.HasVPMSUMD

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
