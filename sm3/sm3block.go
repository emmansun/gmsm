package sm3

import "math/bits"


const (
	_T0 = 0x79cc4519
	_T1 = 0x7a879d8a
)


func p1(x uint32) uint32 {
	return x ^ bits.RotateLeft32(x, 15) ^ bits.RotateLeft32(x, 23)
}

func blockGeneric(dig *digest, p []byte) {
	var w [68]uint32
	h0, h1, h2, h3, h4, h5, h6, h7 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7]

	for len(p) >= chunk {
		// first 16 words handling
		w[0] = uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])
		w[1] = uint32(p[4])<<24 | uint32(p[4+1])<<16 | uint32(p[4+2])<<8 | uint32(p[4+3])
		w[2] = uint32(p[8])<<24 | uint32(p[8+1])<<16 | uint32(p[8+2])<<8 | uint32(p[8+3])
		w[3] = uint32(p[12])<<24 | uint32(p[12+1])<<16 | uint32(p[12+2])<<8 | uint32(p[12+3])
		w[4] = uint32(p[16])<<24 | uint32(p[16+1])<<16 | uint32(p[16+2])<<8 | uint32(p[16+3])
		w[5] = uint32(p[20])<<24 | uint32(p[20+1])<<16 | uint32(p[20+2])<<8 | uint32(p[20+3])
		w[6] = uint32(p[24])<<24 | uint32(p[24+1])<<16 | uint32(p[24+2])<<8 | uint32(p[24+3])
		w[7] = uint32(p[28])<<24 | uint32(p[28+1])<<16 | uint32(p[28+2])<<8 | uint32(p[28+3])
		w[8] = uint32(p[32])<<24 | uint32(p[32+1])<<16 | uint32(p[32+2])<<8 | uint32(p[32+3])
		w[9] = uint32(p[36])<<24 | uint32(p[36+1])<<16 | uint32(p[36+2])<<8 | uint32(p[36+3])
		w[10] = uint32(p[40])<<24 | uint32(p[40+1])<<16 | uint32(p[40+2])<<8 | uint32(p[40+3])
		w[11] = uint32(p[44])<<24 | uint32(p[44+1])<<16 | uint32(p[44+2])<<8 | uint32(p[44+3])
		w[12] = uint32(p[48])<<24 | uint32(p[48+1])<<16 | uint32(p[48+2])<<8 | uint32(p[48+3])
		w[13] = uint32(p[52])<<24 | uint32(p[52+1])<<16 | uint32(p[52+2])<<8 | uint32(p[52+3])
		w[14] = uint32(p[56])<<24 | uint32(p[56+1])<<16 | uint32(p[56+2])<<8 | uint32(p[56+3])
		w[15] = uint32(p[60])<<24 | uint32(p[60+1])<<16 | uint32(p[60+2])<<8 | uint32(p[60+3])

		// init state
		a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7

		// handle first 12 rounds state
		for i := 0; i < 12; i++ {
			ss1 := bits.RotateLeft32(bits.RotateLeft32(a, 12)+e+bits.RotateLeft32(_T0, i), 7)
			ss2 := ss1 ^ bits.RotateLeft32(a, 12)
			tt1 := a ^ b ^ c + d + ss2 + (w[i] ^ w[i+4])
			tt2 := e ^ f ^ g + h + ss1 + w[i]
			d = c
			c = bits.RotateLeft32(b, 9)
			b = a
			a = tt1
			h = g
			g = bits.RotateLeft32(f, 19)
			f = e
			e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)
		}

		// handle next 4 rounds state
		for i := 12; i < 16; i++ {
			w[i+4] = p1(w[i-12]^w[i-5]^bits.RotateLeft32(w[i+1], 15)) ^ bits.RotateLeft32(w[i-9], 7) ^ w[i-2]
			ss1 := bits.RotateLeft32(bits.RotateLeft32(a, 12)+e+bits.RotateLeft32(_T0, i), 7)
			ss2 := ss1 ^ bits.RotateLeft32(a, 12)
			tt1 := a ^ b ^ c + d + ss2 + (w[i] ^ w[i+4])
			tt2 := e ^ f ^ g + h + ss1 + w[i]
			d = c
			c = bits.RotateLeft32(b, 9)
			b = a
			a = tt1
			h = g
			g = bits.RotateLeft32(f, 19)
			f = e
			e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)
		}

		// handle last 48 rounds state
		for i := 16; i < 64; i++ {
			w[i+4] = p1(w[i-12]^w[i-5]^bits.RotateLeft32(w[i+1], 15)) ^ bits.RotateLeft32(w[i-9], 7) ^ w[i-2]
			ss1 := bits.RotateLeft32(bits.RotateLeft32(a, 12)+e+bits.RotateLeft32(_T1, i), 7)
			ss2 := ss1 ^ bits.RotateLeft32(a, 12)
			tt1 := (a & b) | (a & c) | (b & c) + d + ss2 + (w[i] ^ w[i+4])
			tt2 := (e & f) | (^e & g) + h + ss1 + w[i]
			d = c
			c = bits.RotateLeft32(b, 9)
			b = a
			a = tt1
			h = g
			g = bits.RotateLeft32(f, 19)
			f = e
			e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)
		}

		// restore state
		h0 ^= a
		h1 ^= b
		h2 ^= c
		h3 ^= d
		h4 ^= e
		h5 ^= f
		h6 ^= g
		h7 ^= h
		// next chunk
		p = p[chunk:]
	}
	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7] = h0, h1, h2, h3, h4, h5, h6, h7
}
