package sm4

// [GM/T] SM4 GB/T 32907-2016

import (
	"encoding/binary"
)

// Encrypt one block from src into dst, using the expanded key xk.
func encryptBlockGo(xk []uint32, dst, src []byte) {
	_ = src[15]    // early bounds check
	dst = dst[:16] // early bounds check
	_ = xk[31]     // bounds check elimination hint

	var b0, b1, b2, b3 uint32
	b0 = binary.BigEndian.Uint32(src[0:4])
	b1 = binary.BigEndian.Uint32(src[4:8])
	b2 = binary.BigEndian.Uint32(src[8:12])
	b3 = binary.BigEndian.Uint32(src[12:16])

	b0 ^= t(b1 ^ b2 ^ b3 ^ xk[0])
	b1 ^= t(b2 ^ b3 ^ b0 ^ xk[1])
	b2 ^= t(b3 ^ b0 ^ b1 ^ xk[2])
	b3 ^= t(b0 ^ b1 ^ b2 ^ xk[3])

	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[4])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[5])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[6])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[7])

	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[8])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[9])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[10])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[11])

	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[12])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[13])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[14])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[15])

	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[16])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[17])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[18])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[19])

	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[20])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[21])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[22])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[23])

	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[24])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[25])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[26])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[27])

	b0 ^= t(b1 ^ b2 ^ b3 ^ xk[28])
	b1 ^= t(b2 ^ b3 ^ b0 ^ xk[29])
	b2 ^= t(b3 ^ b0 ^ b1 ^ xk[30])
	b3 ^= t(b0 ^ b1 ^ b2 ^ xk[31])

	binary.BigEndian.PutUint32(dst[:], b3)
	binary.BigEndian.PutUint32(dst[4:], b2)
	binary.BigEndian.PutUint32(dst[8:], b1)
	binary.BigEndian.PutUint32(dst[12:], b0)
}

// Key expansion algorithm.
func expandKeyGo(key []byte, enc, dec []uint32) {
	// Encryption key setup.
	enc = enc[:rounds]
	dec = dec[:rounds]
	key = key[:KeySize]
	var b0, b1, b2, b3 uint32
	b0 = binary.BigEndian.Uint32(key[:4]) ^ fk[0]
	b1 = binary.BigEndian.Uint32(key[4:8]) ^ fk[1]
	b2 = binary.BigEndian.Uint32(key[8:12]) ^ fk[2]
	b3 = binary.BigEndian.Uint32(key[12:16]) ^ fk[3]

	b0 = b0 ^ t2(b1^b2^b3^ck[0])
	enc[0], dec[31] = b0, b0
	b1 = b1 ^ t2(b2^b3^b0^ck[1])
	enc[1], dec[30] = b1, b1
	b2 = b2 ^ t2(b3^b0^b1^ck[2])
	enc[2], dec[29] = b2, b2
	b3 = b3 ^ t2(b0^b1^b2^ck[3])
	enc[3], dec[28] = b3, b3

	b0 = b0 ^ t2(b1^b2^b3^ck[4])
	enc[4], dec[27] = b0, b0
	b1 = b1 ^ t2(b2^b3^b0^ck[5])
	enc[5], dec[26] = b1, b1
	b2 = b2 ^ t2(b3^b0^b1^ck[6])
	enc[6], dec[25] = b2, b2
	b3 = b3 ^ t2(b0^b1^b2^ck[7])
	enc[7], dec[24] = b3, b3

	b0 = b0 ^ t2(b1^b2^b3^ck[8])
	enc[8], dec[23] = b0, b0
	b1 = b1 ^ t2(b2^b3^b0^ck[9])
	enc[9], dec[22] = b1, b1
	b2 = b2 ^ t2(b3^b0^b1^ck[10])
	enc[10], dec[21] = b2, b2
	b3 = b3 ^ t2(b0^b1^b2^ck[11])
	enc[11], dec[20] = b3, b3

	b0 = b0 ^ t2(b1^b2^b3^ck[12])
	enc[12], dec[19] = b0, b0
	b1 = b1 ^ t2(b2^b3^b0^ck[13])
	enc[13], dec[18] = b1, b1
	b2 = b2 ^ t2(b3^b0^b1^ck[14])
	enc[14], dec[17] = b2, b2
	b3 = b3 ^ t2(b0^b1^b2^ck[15])
	enc[15], dec[16] = b3, b3

	b0 = b0 ^ t2(b1^b2^b3^ck[16])
	enc[16], dec[15] = b0, b0
	b1 = b1 ^ t2(b2^b3^b0^ck[17])
	enc[17], dec[14] = b1, b1
	b2 = b2 ^ t2(b3^b0^b1^ck[18])
	enc[18], dec[13] = b2, b2
	b3 = b3 ^ t2(b0^b1^b2^ck[19])
	enc[19], dec[12] = b3, b3

	b0 = b0 ^ t2(b1^b2^b3^ck[20])
	enc[20], dec[11] = b0, b0
	b1 = b1 ^ t2(b2^b3^b0^ck[21])
	enc[21], dec[10] = b1, b1
	b2 = b2 ^ t2(b3^b0^b1^ck[22])
	enc[22], dec[9] = b2, b2
	b3 = b3 ^ t2(b0^b1^b2^ck[23])
	enc[23], dec[8] = b3, b3

	b0 = b0 ^ t2(b1^b2^b3^ck[24])
	enc[24], dec[7] = b0, b0
	b1 = b1 ^ t2(b2^b3^b0^ck[25])
	enc[25], dec[6] = b1, b1
	b2 = b2 ^ t2(b3^b0^b1^ck[26])
	enc[26], dec[5] = b2, b2
	b3 = b3 ^ t2(b0^b1^b2^ck[27])
	enc[27], dec[4] = b3, b3

	b0 = b0 ^ t2(b1^b2^b3^ck[28])
	enc[28], dec[3] = b0, b0
	b1 = b1 ^ t2(b2^b3^b0^ck[29])
	enc[29], dec[2] = b1, b1
	b2 = b2 ^ t2(b3^b0^b1^ck[30])
	enc[30], dec[1] = b2, b2
	b3 = b3 ^ t2(b0^b1^b2^ck[31])
	enc[31], dec[0] = b3, b3
}

// Decrypt one block from src into dst, using the expanded key xk.
func decryptBlockGo(xk []uint32, dst, src []byte) {
	encryptBlockGo(xk, dst, src)
}

// T
func t(in uint32) uint32 {
	var b uint32

	b = uint32(sbox[in&0xff])
	b |= uint32(sbox[(in>>8)&0xff]) << 8
	b |= uint32(sbox[(in>>16)&0xff]) << 16
	b |= uint32(sbox[(in>>24)&0xff]) << 24

	// L
	return b ^ (b<<2 | b>>30) ^ (b<<10 | b>>22) ^ (b<<18 | b>>14) ^ (b<<24 | b>>8)
}

// T'
func t2(in uint32) uint32 {
	var b uint32

	b = uint32(sbox[in&0xff])
	b |= uint32(sbox[(in>>8)&0xff]) << 8
	b |= uint32(sbox[(in>>16)&0xff]) << 16
	b |= uint32(sbox[(in>>24)&0xff]) << 24

	// L2
	return b ^ (b<<13 | b>>19) ^ (b<<23 | b>>9)
}

func precompute_t(in uint32) uint32 {
	return sbox_t0[byte(in>>24)] ^
		sbox_t1[byte(in>>16)] ^
		sbox_t2[byte(in>>8)] ^
		sbox_t3[byte(in)]
}
