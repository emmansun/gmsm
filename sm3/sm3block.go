package sm3

import "math/bits"

var _T = []uint32{
	0x79cc4519,
	0x7a879d8a,
}

func p0(x uint32) uint32 {
	return x ^ bits.RotateLeft32(x, 9) ^ bits.RotateLeft32(x, 17)
}

func p1(x uint32) uint32 {
	return x ^ bits.RotateLeft32(x, 15) ^ bits.RotateLeft32(x, 23)
}

func ff(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func gg(x, y, z uint32) uint32 {
	return (x & y) | (^x & z)
}

func blockGeneric(dig *digest, p []byte) {
	var w [68]uint32
	h0, h1, h2, h3, h4, h5, h6, h7 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7]
	for len(p) >= chunk {
		for i := 0; i < 4; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}
		a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7
		for i := 0; i < 12; i++ {
			j := (i + 4) * 4
			w[i+4] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
			ss1 := bits.RotateLeft32(bits.RotateLeft32(a, 12)+e+bits.RotateLeft32(_T[0], i), 7)
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
			e = p0(tt2)
		}
	
		for i := 12; i < 16; i++ {
			w[i+4] = p1(w[i-12]^w[i-5]^bits.RotateLeft32(w[i+1], 15)) ^ bits.RotateLeft32(w[i-9], 7) ^ w[i-2]
			ss1 := bits.RotateLeft32(bits.RotateLeft32(a, 12)+e+bits.RotateLeft32(_T[0], i), 7)
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
			e = p0(tt2)
		}

		for i := 16; i < 64; i++ {
			w[i+4] = p1(w[i-12]^w[i-5]^bits.RotateLeft32(w[i+1], 15)) ^ bits.RotateLeft32(w[i-9], 7) ^ w[i-2]
			ss1 := bits.RotateLeft32(bits.RotateLeft32(a, 12)+e+bits.RotateLeft32(_T[1], i), 7)
			ss2 := ss1 ^ bits.RotateLeft32(a, 12)
			tt1 := ff(a, b, c) + d + ss2 + (w[i] ^ w[i+4])
			tt2 := gg(e, f, g) + h + ss1 + w[i]

			d = c
			c = bits.RotateLeft32(b, 9)
			b = a
			a = tt1
			h = g
			g = bits.RotateLeft32(f, 19)
			f = e
			e = p0(tt2)
		}
		h0 ^= a
		h1 ^= b
		h2 ^= c
		h3 ^= d
		h4 ^= e
		h5 ^= f
		h6 ^= g
		h7 ^= h
		p = p[chunk:]
	}
	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7] = h0, h1, h2, h3, h4, h5, h6, h7
}
