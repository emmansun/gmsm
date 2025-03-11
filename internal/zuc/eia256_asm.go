//go:build (amd64 || arm64 || ppc64 || ppc64le) && !purego

package zuc

//go:noescape
func eia256RoundTag8(t *uint32, keyStream *uint32, p *byte)

//go:noescape
func eia256RoundTag16(t *uint32, keyStream *uint32, p *byte)

func block256(m *ZUC256Mac, p []byte) {
	if supportsGFMUL {
		for len(p) >= chunk {
			m.genKeywords(m.k0[4:])
			switch m.tagSize {
			case 8:
				eia256RoundTag8(&m.t[0], &m.k0[0], &p[0])
			case 16:
				eia256RoundTag16(&m.t[0], &m.k0[0], &p[0])
			default:
				eiaRoundTag4(&m.t[0], &m.k0[0], &p[0])
			}
			p = p[chunk:]
		}
	} else {
		block256Generic(m, p)
	}
}
