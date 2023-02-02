package zuc

import (
	"encoding/binary"
	"fmt"
)

type ZUC256Mac struct {
	zucState32
	k0        [8]uint32
	t         []uint32
	x         [chunk]byte
	nx        int
	len       uint64
	tagSize   int
	initState zucState32
}

// NewHash256 create hash for zuc-256 eia, with arguments key, iv and tagSize.
// Key size is 32 in bytes, iv size is 23 in bytes, tagSize supports 4/8/16 in bytes.
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
	switch k {
	default:
		return nil, fmt.Errorf("zuc/eia: invalid key size %d, expect 32 in bytes", k)
	case 32: // ZUC-256
		if ivLen != IVSize256 {
			return nil, fmt.Errorf("zuc/eia: invalid iv size %d, expect %d in bytes", ivLen, IVSize256)
		}
		mac.loadKeyIV32(key, iv, d)
	}
	// initialization
	for i := 0; i < 32; i++ {
		mac.bitReorganization()
		w := mac.f32()
		mac.enterInitMode(w >> 1)
	}

	// work state
	mac.bitReorganization()
	mac.f32()
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

// Reset resets the Hash to its initial state.
func (m *ZUC256Mac) Reset() {
	m.nx = 0
	m.len = 0
	m.r1 = m.initState.r1
	m.r2 = m.initState.r2
	copy(m.lfsr[:], m.initState.lfsr[:])
	m.genKeywords(m.t)
	m.genKeywords(m.k0[:4])
}

func block256Generic(m *ZUC256Mac, p []byte) {
	var k64, t64 uint64
	if m.tagSize == 4 {
		t64 = uint64(m.t[0]) << 32
	}
	tagWords := m.tagSize / 4
	for len(p) >= chunk {
		m.genKeywords(m.k0[4:])
		for l := 0; l < 4; l++ {
			w := binary.BigEndian.Uint32(p[l*4:])
			switch m.tagSize {
			case 4:
				k64 = uint64(m.k0[l])<<32 | uint64(m.k0[l+1])
				for j := 0; j < 32; j++ {
					t64 ^= ^(uint64(w>>31) - 1) & k64
					w <<= 1
					k64 <<= 1
				}
			default:
				k1 := m.k0[tagWords+l]
				for i := 0; i < 32; i++ {
					wBit := ^(w>>31 - 1)
					for j := 0; j < tagWords; j++ {
						m.t[j] ^= wBit & m.k0[j]
					}
					w <<= 1
					var j int
					for j = 0; j < tagWords-1; j++ {
						m.k0[j] = (m.k0[j] << 1) | (m.k0[j+1] >> 31)
					}
					m.k0[j] = (m.k0[j] << 1) | (k1 >> 31)
					k1 <<= 1
				}
			}
		}
		if tagWords != 4 {
			copy(m.k0[:4], m.k0[4:])
		}
		p = p[chunk:]
	}
	if m.tagSize == 4 {
		m.t[0] = uint32(t64 >> 32)
	}
}

func (m *ZUC256Mac) Write(p []byte) (nn int, err error) {
	nn = len(p)
	m.len += uint64(nn)
	if m.nx > 0 {
		n := copy(m.x[m.nx:], p)
		m.nx += n
		if m.nx == chunk {
			block256(m, m.x[:])
			m.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block256(m, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		m.nx = copy(m.x[:], p)
	}
	return
}

func (m *ZUC256Mac) checkSum(additionalBits int, b byte) []byte {
	if m.nx >= chunk {
		panic("m.nx >= 16")
	}
	kIdx := 0
	if m.nx > 0 || additionalBits > 0 {
		m.x[m.nx] = b
		m.genKeywords(m.k0[4:])
		nRemainBits := 8*m.nx + additionalBits
		words := (nRemainBits + 31) / 32

		for l := 0; l < words-1; l++ {
			w := binary.BigEndian.Uint32(m.x[l*4:])
			k1 := m.k0[m.tagSize/4+l]
			for i := 0; i < 32; i++ {
				wBit := ^(w>>31 - 1)
				for j := 0; j < m.tagSize/4; j++ {
					m.t[j] ^= wBit & m.k0[j]
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
		nRemainBits -= (words - 1) * 32
		kIdx = words - 1
		if nRemainBits > 0 {
			w := binary.BigEndian.Uint32(m.x[(words-1)*4:])
			for i := 0; i < nRemainBits; i++ {
				wBit := ^(w>>31 - 1)
				for j := 0; j < m.tagSize/4; j++ {
					m.t[j] ^= wBit & m.k0[j+kIdx]
				}
				w <<= 1
				var j int
				for j = 0; j < m.tagSize/4; j++ {
					m.k0[j+kIdx] = (m.k0[j+kIdx] << 1) | (m.k0[kIdx+j+1] >> 31)
				}
				m.k0[j+kIdx] <<= 1
			}
		}
	}

	digest := make([]byte, m.tagSize)
	for j := 0; j < m.tagSize/4; j++ {
		m.t[j] ^= m.k0[j+kIdx]
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

// Sum appends the current hash to in and returns the resulting slice.
// It does not change the underlying hash state.
func (m *ZUC256Mac) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *m
	d0.t = make([]uint32, len(m.t))
	copy(d0.t, m.t)
	hash := d0.checkSum(0, 0)
	return append(in, hash[:]...)
}
