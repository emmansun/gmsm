package zuc

import (
	"encoding/binary"
	"fmt"
)

type ZUC256Mac struct {
	zucState32
	initState zucState32
	tagSize   int
	k0        []uint32
	t         []uint32
	x         [chunk]byte
	nx        int
	len       uint64
}

// NewHash create hash for zuc-128 eia, with arguments key, iv and tagSize.
// The larger the tag size, the worse the performance.
func NewHash256(key, iv []byte, tagSize int) (*ZUC256Mac, error) {
	k := len(key)
	ivLen := len(iv)
	mac := &ZUC256Mac{}
	var d []byte
	switch tagSize {
	default:
		return nil, fmt.Errorf("zuc/eia: invalid tag size %d, support 4/8/16 in bytes", tagSize)
	case 4:
		d = zuc256_d[0][:]
	case 8:
		d = zuc256_d[1][:]
	case 16:
		d = zuc256_d[2][:]
	}
	mac.tagSize = tagSize
	mac.t = make([]uint32, mac.tagSize/4)
	mac.k0 = make([]uint32, mac.tagSize/4)
	switch k {
	default:
		return nil, fmt.Errorf("zuc/eia: invalid key size %d, expect 32 in bytes", k)
	case 32: // ZUC-256
		if ivLen != 23 {
			return nil, fmt.Errorf("zuc/eia: invalid iv size %d, expect 23 in bytes", ivLen)
		}
		mac.loadKeyIV32(key, iv, d)
	}
	// initialization
	for i := 0; i < 32; i++ {
		x := mac.bitReconstruction()
		w := mac.f32(x[0], x[1], x[2])
		mac.enterInitMode(w >> 1)
	}

	// work state
	x := mac.bitReconstruction()
	mac.f32(x[0], x[1], x[2])
	mac.enterWorkMode()

	mac.initState.r1 = mac.r1
	mac.initState.r2 = mac.r2

	copy(mac.initState.lfsr[:], mac.lfsr[:])
	mac.Reset()
	return mac, nil
}

func (m *ZUC256Mac) Size() int {
	return m.tagSize
}

func (m *ZUC256Mac) BlockSize() int {
	return chunk
}

func (m *ZUC256Mac) Reset() {
	m.nx = 0
	m.len = 0
	m.r1 = m.initState.r1
	m.r2 = m.initState.r2
	copy(m.lfsr[:], m.initState.lfsr[:])
	m.genKeywords(m.t)
	m.genKeywords(m.k0)
}

func (m *ZUC256Mac) block(p []byte) {
	for len(p) >= chunk {
		w := binary.BigEndian.Uint32(p)
		k1 := m.genKeyword()

		for i := 0; i < 32; i++ {
			if w&0x80000000 == 0x80000000 {
				for j := 0; j < m.tagSize/4; j++ {
					m.t[j] ^= m.k0[j]
				}
			}
			w <<= 1
			var j int
			for j = 0; j < m.tagSize/4-1; j++ {
				m.k0[j] = (m.k0[j] << 1) | (m.k0[j+1] >> 31)
			}
			m.k0[j] = (m.k0[j] << 1) | (k1 >> 31)
			k1 <<= 1
		}

		p = p[chunk:]
	}
}

func (m *ZUC256Mac) Write(p []byte) (nn int, err error) {
	nn = len(p)
	m.len += uint64(nn)
	if m.nx > 0 {
		n := copy(m.x[m.nx:], p)
		m.nx += n
		if m.nx == chunk {
			m.block(m.x[:])
			m.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		m.block(p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		m.nx = copy(m.x[:], p)
	}
	return
}

func (m *ZUC256Mac) checkSum(additionalBits int, b byte) []byte {
	if m.nx >= 4 {
		panic("m.nx >= 4")
	}
	if m.nx > 0 || additionalBits > 0 {
		m.x[m.nx] = b
		w := binary.BigEndian.Uint32(m.x[:])
		k1 := m.genKeyword()

		for i := 0; i < 8*m.nx+additionalBits; i++ {
			if w&0x80000000 == 0x80000000 {
				for j := 0; j < m.tagSize/4; j++ {
					m.t[j] ^= m.k0[j]
				}
			}
			w <<= 1
			var j int
			for j = 0; j < m.tagSize/4-1; j++ {
				m.k0[j] = (m.k0[j] << 1) | (m.k0[j+1] >> 31)
			}
			m.k0[j] = (m.k0[j] << 1) | (k1 >> 31)
			k1 <<= 1
		}
	}

	digest := make([]byte, m.tagSize)
	for j := 0; j < m.tagSize/4; j++ {
		m.t[j] ^= m.k0[j]
		binary.BigEndian.PutUint32(digest[j*4:], m.t[j])
	}

	return digest
}

// Finish this function hash nbits data in p and return mac value
// In general, we will use byte level function, this is just for test/verify.
func (m *ZUC256Mac) Finish(p []byte, nbits int) []byte {
	if len(p) < (nbits+7)/8 {
		panic("invalid p length")
	}
	nbytes := nbits / 8
	nRemainBits := nbits - nbytes*8
	if nbytes > 0 {
		m.Write(p[:nbytes])
	}
	var b byte
	if nRemainBits > 0 {
		b = p[nbytes]
	}
	digest := m.checkSum(nRemainBits, b)
	return digest[:]
}

func (m *ZUC256Mac) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *m
	hash := d0.checkSum(0, 0)
	return append(in, hash[:]...)
}
