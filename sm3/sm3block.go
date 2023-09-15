package sm3

import "math/bits"

const (
	_T0 = 0x79cc4519
	_T1 = 0x7a879d8a
)

var _K = [64]uint32{
	0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
	0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
	0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
	0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
	0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
	0x879d8a7a, 0xf3b14f5, 0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
	0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
	0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
}

func p1(x uint32) uint32 {
	return x ^ (x<<15 | x>>17) ^ (x<<23 | x>>9)
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

		// Round 1
		tt2 := bits.RotateLeft32(a, 12)
		ss1 := bits.RotateLeft32(tt2+e+_K[0], 7)
		d = a ^ b ^ c + d + (ss1 ^ tt2) + (w[0] ^ w[4])
		tt2 = e ^ f ^ g + h + ss1 + w[0]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 2
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[1], 7)
		c = d ^ a ^ b + c + (ss1 ^ tt2) + (w[1] ^ w[5])
		tt2 = h ^ e ^ f + g + ss1 + w[1]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 3
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[2], 7)
		b = c ^ d ^ a + b + (ss1 ^ tt2) + (w[2] ^ w[6])
		tt2 = g ^ h ^ e + f + ss1 + w[2]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 4
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[3], 7)
		a = b ^ c ^ d + a + (ss1 ^ tt2) + (w[3] ^ w[7])
		tt2 = f ^ g ^ h + e + ss1 + w[3]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 5
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[4], 7)
		d = a ^ b ^ c + d + (ss1 ^ tt2) + (w[4] ^ w[8])
		tt2 = e ^ f ^ g + h + ss1 + w[4]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 6
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[5], 7)
		c = d ^ a ^ b + c + (ss1 ^ tt2) + (w[5] ^ w[9])
		tt2 = h ^ e ^ f + g + ss1 + w[5]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 7
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[6], 7)
		b = c ^ d ^ a + b + (ss1 ^ tt2) + (w[6] ^ w[10])
		tt2 = g ^ h ^ e + f + ss1 + w[6]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 8
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[7], 7)
		a = b ^ c ^ d + a + (ss1 ^ tt2) + (w[7] ^ w[11])
		tt2 = f ^ g ^ h + e + ss1 + w[7]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 9
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[8], 7)
		d = a ^ b ^ c + d + (ss1 ^ tt2) + (w[8] ^ w[12])
		tt2 = e ^ f ^ g + h + ss1 + w[8]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 10
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[9], 7)
		c = d ^ a ^ b + c + (ss1 ^ tt2) + (w[9] ^ w[13])
		tt2 = h ^ e ^ f + g + ss1 + w[9]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 11
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[10], 7)
		b = c ^ d ^ a + b + (ss1 ^ tt2) + (w[10] ^ w[14])
		tt2 = g ^ h ^ e + f + ss1 + w[10]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 12
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[11], 7)
		a = b ^ c ^ d + a + (ss1 ^ tt2) + (w[11] ^ w[15])
		tt2 = f ^ g ^ h + e + ss1 + w[11]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 13
		w[16] = p1(w[0]^w[7]^bits.RotateLeft32(w[13], 15)) ^ bits.RotateLeft32(w[3], 7) ^ w[10]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[12], 7)
		d = a ^ b ^ c + d + (ss1 ^ tt2) + (w[12] ^ w[16])
		tt2 = e ^ f ^ g + h + ss1 + w[12]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 14
		w[17] = p1(w[1]^w[8]^bits.RotateLeft32(w[14], 15)) ^ bits.RotateLeft32(w[4], 7) ^ w[11]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[13], 7)
		c = d ^ a ^ b + c + (ss1 ^ tt2) + (w[13] ^ w[17])
		tt2 = h ^ e ^ f + g + ss1 + w[13]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 15
		w[18] = p1(w[2]^w[9]^bits.RotateLeft32(w[15], 15)) ^ bits.RotateLeft32(w[5], 7) ^ w[12]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[14], 7)
		b = c ^ d ^ a + b + (ss1 ^ tt2) + (w[14] ^ w[18])
		tt2 = g ^ h ^ e + f + ss1 + w[14]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 16
		w[19] = p1(w[3]^w[10]^bits.RotateLeft32(w[16], 15)) ^ bits.RotateLeft32(w[6], 7) ^ w[13]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[15], 7)
		a = b ^ c ^ d + a + (ss1 ^ tt2) + (w[15] ^ w[19])
		tt2 = f ^ g ^ h + e + ss1 + w[15]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 17
		w[20] = p1(w[4]^w[11]^bits.RotateLeft32(w[17], 15)) ^ bits.RotateLeft32(w[7], 7) ^ w[14]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[16], 7)
		d = c&(a|b) | (a & b) + d + (ss1 ^ tt2) + (w[16] ^ w[20])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[16]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 18
		w[21] = p1(w[5]^w[12]^bits.RotateLeft32(w[18], 15)) ^ bits.RotateLeft32(w[8], 7) ^ w[15]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[17], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[17] ^ w[21])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[17]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 19
		w[22] = p1(w[6]^w[13]^bits.RotateLeft32(w[19], 15)) ^ bits.RotateLeft32(w[9], 7) ^ w[16]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[18], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[18] ^ w[22])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[18]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 20
		w[23] = p1(w[7]^w[14]^bits.RotateLeft32(w[20], 15)) ^ bits.RotateLeft32(w[10], 7) ^ w[17]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[19], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[19] ^ w[23])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[19]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 21
		w[24] = p1(w[8]^w[15]^bits.RotateLeft32(w[21], 15)) ^ bits.RotateLeft32(w[11], 7) ^ w[18]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[20], 7)
		d = a&(b|c) | (b & c) + d + (ss1 ^ tt2) + (w[20] ^ w[24])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[20]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 22
		w[25] = p1(w[9]^w[16]^bits.RotateLeft32(w[22], 15)) ^ bits.RotateLeft32(w[12], 7) ^ w[19]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[21], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[21] ^ w[25])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[21]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 23
		w[26] = p1(w[10]^w[17]^bits.RotateLeft32(w[23], 15)) ^ bits.RotateLeft32(w[13], 7) ^ w[20]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[22], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[22] ^ w[26])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[22]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 24
		w[27] = p1(w[11]^w[18]^bits.RotateLeft32(w[24], 15)) ^ bits.RotateLeft32(w[14], 7) ^ w[21]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[23], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[23] ^ w[27])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[23]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 25
		w[28] = p1(w[12]^w[19]^bits.RotateLeft32(w[25], 15)) ^ bits.RotateLeft32(w[15], 7) ^ w[22]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[24], 7)
		d = a&(b|c) | (b & c) + d + (ss1 ^ tt2) + (w[24] ^ w[28])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[24]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 26
		w[29] = p1(w[13]^w[20]^bits.RotateLeft32(w[26], 15)) ^ bits.RotateLeft32(w[16], 7) ^ w[23]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[25], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[25] ^ w[29])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[25]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 27
		w[30] = p1(w[14]^w[21]^bits.RotateLeft32(w[27], 15)) ^ bits.RotateLeft32(w[17], 7) ^ w[24]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[26], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[26] ^ w[30])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[26]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 28
		w[31] = p1(w[15]^w[22]^bits.RotateLeft32(w[28], 15)) ^ bits.RotateLeft32(w[18], 7) ^ w[25]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[27], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[27] ^ w[31])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[27]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 29
		w[32] = p1(w[16]^w[23]^bits.RotateLeft32(w[29], 15)) ^ bits.RotateLeft32(w[19], 7) ^ w[26]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[28], 7)
		d = a&(b|c) | (b & c) + d + (ss1 ^ tt2) + (w[28] ^ w[32])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[28]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 30
		w[33] = p1(w[17]^w[24]^bits.RotateLeft32(w[30], 15)) ^ bits.RotateLeft32(w[20], 7) ^ w[27]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[29], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[29] ^ w[33])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[29]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 31
		w[34] = p1(w[18]^w[25]^bits.RotateLeft32(w[31], 15)) ^ bits.RotateLeft32(w[21], 7) ^ w[28]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[30], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[30] ^ w[34])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[30]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 32
		w[35] = p1(w[19]^w[26]^bits.RotateLeft32(w[32], 15)) ^ bits.RotateLeft32(w[22], 7) ^ w[29]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[31], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[31] ^ w[35])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[31]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 33
		w[36] = p1(w[20]^w[27]^bits.RotateLeft32(w[33], 15)) ^ bits.RotateLeft32(w[23], 7) ^ w[30]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[32], 7)
		d = a&(b|c) | (b & c) + d + (ss1 ^ tt2) + (w[32] ^ w[36])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[32]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 34
		w[37] = p1(w[21]^w[28]^bits.RotateLeft32(w[34], 15)) ^ bits.RotateLeft32(w[24], 7) ^ w[31]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[33], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[33] ^ w[37])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[33]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 35
		w[38] = p1(w[22]^w[29]^bits.RotateLeft32(w[35], 15)) ^ bits.RotateLeft32(w[25], 7) ^ w[32]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[34], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[34] ^ w[38])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[34]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 36
		w[39] = p1(w[23]^w[30]^bits.RotateLeft32(w[36], 15)) ^ bits.RotateLeft32(w[26], 7) ^ w[33]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[35], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[35] ^ w[39])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[35]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 37
		w[40] = p1(w[24]^w[31]^bits.RotateLeft32(w[37], 15)) ^ bits.RotateLeft32(w[27], 7) ^ w[34]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[36], 7)
		d = a&(b|c) | (b & c) + d + (ss1 ^ tt2) + (w[36] ^ w[40])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[36]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 38
		w[41] = p1(w[25]^w[32]^bits.RotateLeft32(w[38], 15)) ^ bits.RotateLeft32(w[28], 7) ^ w[35]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[37], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[37] ^ w[41])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[37]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 39
		w[42] = p1(w[26]^w[33]^bits.RotateLeft32(w[39], 15)) ^ bits.RotateLeft32(w[29], 7) ^ w[36]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[38], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[38] ^ w[42])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[38]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 40
		w[43] = p1(w[27]^w[34]^bits.RotateLeft32(w[40], 15)) ^ bits.RotateLeft32(w[30], 7) ^ w[37]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[39], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[39] ^ w[43])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[39]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 41
		w[44] = p1(w[28]^w[35]^bits.RotateLeft32(w[41], 15)) ^ bits.RotateLeft32(w[31], 7) ^ w[38]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[40], 7)
		d = a&(b|c) | (b & c) + d + (ss1 ^ tt2) + (w[40] ^ w[44])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[40]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)
		// Round 42
		w[45] = p1(w[29]^w[36]^bits.RotateLeft32(w[42], 15)) ^ bits.RotateLeft32(w[32], 7) ^ w[39]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[41], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[41] ^ w[45])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[41]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 43
		w[46] = p1(w[30]^w[37]^bits.RotateLeft32(w[43], 15)) ^ bits.RotateLeft32(w[33], 7) ^ w[40]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[42], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[42] ^ w[46])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[42]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 44
		w[47] = p1(w[31]^w[38]^bits.RotateLeft32(w[44], 15)) ^ bits.RotateLeft32(w[34], 7) ^ w[41]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[43], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[43] ^ w[47])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[43]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 45
		w[48] = p1(w[32]^w[39]^bits.RotateLeft32(w[45], 15)) ^ bits.RotateLeft32(w[35], 7) ^ w[42]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[44], 7)
		d = a&(b|c) | (b & c) + d + (ss1 ^ tt2) + (w[44] ^ w[48])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[44]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 46
		w[49] = p1(w[33]^w[40]^bits.RotateLeft32(w[46], 15)) ^ bits.RotateLeft32(w[36], 7) ^ w[43]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[45], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[45] ^ w[49])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[45]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 47
		w[50] = p1(w[34]^w[41]^bits.RotateLeft32(w[47], 15)) ^ bits.RotateLeft32(w[37], 7) ^ w[44]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[46], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[46] ^ w[50])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[46]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 48
		w[51] = p1(w[35]^w[42]^bits.RotateLeft32(w[48], 15)) ^ bits.RotateLeft32(w[38], 7) ^ w[45]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[47], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[47] ^ w[51])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[47]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 49
		w[52] = p1(w[36]^w[43]^bits.RotateLeft32(w[49], 15)) ^ bits.RotateLeft32(w[39], 7) ^ w[46]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[48], 7)
		d = a&(b|c) | (b & c) + d + (ss1 ^ tt2) + (w[48] ^ w[52])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[48]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 50
		w[53] = p1(w[37]^w[44]^bits.RotateLeft32(w[50], 15)) ^ bits.RotateLeft32(w[40], 7) ^ w[47]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[49], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[49] ^ w[53])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[49]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 51
		w[54] = p1(w[38]^w[45]^bits.RotateLeft32(w[51], 15)) ^ bits.RotateLeft32(w[41], 7) ^ w[48]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[50], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[50] ^ w[54])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[50]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 52
		w[55] = p1(w[39]^w[46]^bits.RotateLeft32(w[52], 15)) ^ bits.RotateLeft32(w[42], 7) ^ w[49]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[51], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[51] ^ w[55])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[51]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 53
		w[56] = p1(w[40]^w[47]^bits.RotateLeft32(w[53], 15)) ^ bits.RotateLeft32(w[43], 7) ^ w[50]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[52], 7)
		d = a&(b|c) | (b & c) + d + (ss1 ^ tt2) + (w[52] ^ w[56])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[52]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 54
		w[57] = p1(w[41]^w[48]^bits.RotateLeft32(w[54], 15)) ^ bits.RotateLeft32(w[44], 7) ^ w[51]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[53], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[53] ^ w[57])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[53]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 55
		w[58] = p1(w[42]^w[49]^bits.RotateLeft32(w[55], 15)) ^ bits.RotateLeft32(w[45], 7) ^ w[52]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[54], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[54] ^ w[58])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[54]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 56
		w[59] = p1(w[43]^w[50]^bits.RotateLeft32(w[56], 15)) ^ bits.RotateLeft32(w[46], 7) ^ w[53]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[55], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[55] ^ w[59])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[55]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 57
		w[60] = p1(w[44]^w[51]^bits.RotateLeft32(w[57], 15)) ^ bits.RotateLeft32(w[47], 7) ^ w[54]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[56], 7)
		d = a&(b|c) | (b & c) + d + (ss1 ^ tt2) + (w[56] ^ w[60])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[56]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 58
		w[61] = p1(w[45]^w[52]^bits.RotateLeft32(w[58], 15)) ^ bits.RotateLeft32(w[48], 7) ^ w[55]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[57], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[57] ^ w[61])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[57]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 59
		w[62] = p1(w[46]^w[53]^bits.RotateLeft32(w[59], 15)) ^ bits.RotateLeft32(w[49], 7) ^ w[56]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[58], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[58] ^ w[62])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[58]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 60
		w[63] = p1(w[47]^w[54]^bits.RotateLeft32(w[60], 15)) ^ bits.RotateLeft32(w[50], 7) ^ w[57]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[59], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[59] ^ w[63])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[59]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 61
		w[64] = p1(w[48]^w[55]^bits.RotateLeft32(w[61], 15)) ^ bits.RotateLeft32(w[51], 7) ^ w[58]
		tt2 = bits.RotateLeft32(a, 12)
		ss1 = bits.RotateLeft32(tt2+e+_K[60], 7)
		d = a&(b|c) | (b & c) + d + (ss1 ^ tt2) + (w[60] ^ w[64])
		tt2 = (e & f) | (^e & g) + h + ss1 + w[60]
		b = bits.RotateLeft32(b, 9)
		f = bits.RotateLeft32(f, 19)
		h = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 62
		w[65] = p1(w[49]^w[56]^bits.RotateLeft32(w[62], 15)) ^ bits.RotateLeft32(w[52], 7) ^ w[59]
		tt2 = bits.RotateLeft32(d, 12)
		ss1 = bits.RotateLeft32(tt2+h+_K[61], 7)
		c = d&(a|b) | (a & b) + c + (ss1 ^ tt2) + (w[61] ^ w[65])
		tt2 = (h & e) | (^h & f) + g + ss1 + w[61]
		a = bits.RotateLeft32(a, 9)
		e = bits.RotateLeft32(e, 19)
		g = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 63
		w[66] = p1(w[50]^w[57]^bits.RotateLeft32(w[63], 15)) ^ bits.RotateLeft32(w[53], 7) ^ w[60]
		tt2 = bits.RotateLeft32(c, 12)
		ss1 = bits.RotateLeft32(tt2+g+_K[62], 7)
		b = c&(d|a) | (d & a) + b + (ss1 ^ tt2) + (w[62] ^ w[66])
		tt2 = (g & h) | (^g & e) + f + ss1 + w[62]
		d = bits.RotateLeft32(d, 9)
		h = bits.RotateLeft32(h, 19)
		f = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

		// Round 64
		w[67] = p1(w[51]^w[58]^bits.RotateLeft32(w[64], 15)) ^ bits.RotateLeft32(w[54], 7) ^ w[61]
		tt2 = bits.RotateLeft32(b, 12)
		ss1 = bits.RotateLeft32(tt2+f+_K[63], 7)
		a = b&(c|d) | (c & d) + a + (ss1 ^ tt2) + (w[63] ^ w[67])
		tt2 = (f & g) | (^f & h) + e + ss1 + w[63]
		c = bits.RotateLeft32(c, 9)
		g = bits.RotateLeft32(g, 19)
		e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)

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
