package sm4

import (
	"encoding/binary"
	"math/bits"
)

type convert func(uint32) uint32

// Encrypt one block from src into dst, using the expanded key xk.
func encryptBlockGo(xk []uint32, dst, src []byte) {
	_ = src[15] // early bounds check
	_ = dst[15] // early bounds check
	var x [rounds + 4]uint32
	var i int
	for i = 0; i < 4; i++ {
		x[i] = binary.BigEndian.Uint32(src[4*i:])
	}

	for i = 0; i < rounds; i++ {
		x[i+4] = x[i] ^ t(x[i+1]^x[i+2]^x[i+3]^xk[i])
	}

	for i = rounds + 3; i >= rounds; i-- {
		binary.BigEndian.PutUint32(dst[4*(rounds+3-i):], x[i])
	}
}

// Key expansion algorithm.
func expandKeyGo(key []byte, enc, dec []uint32) {
	// Encryption key setup.
	var i int
	var mk []uint32
	var k [rounds + 4]uint32
	nk := len(key) / 4
	mk = make([]uint32, nk)
	for i = 0; i < nk; i++ {
		mk[i] = binary.BigEndian.Uint32(key[4*i:])
		k[i] = mk[i] ^ fk[i]
	}

	for i = 0; i < rounds; i++ {
		k[i+4] = k[i] ^ t2(k[i+1]^k[i+2]^k[i+3]^ck[i])
		enc[i] = k[i+4]
	}

	// Derive decryption key from encryption key.
	if dec == nil {
		return
	}
	for i = 0; i < rounds; i++ {
		dec[i] = enc[rounds-1-i]
	}
}

// Decrypt one block from src into dst, using the expanded key xk.
func decryptBlockGo(xk []uint32, dst, src []byte) {
	encryptBlockGo(xk, dst, src)
}

//L(B)
func l(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 2) ^ bits.RotateLeft32(b, 10) ^ bits.RotateLeft32(b, 18) ^ bits.RotateLeft32(b, 24)
}

//L'(B)
func l2(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 13) ^ bits.RotateLeft32(b, 23)
}

func _t(in uint32, fn convert) uint32 {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], in)
	for i := 0; i < 4; i++ {
		bytes[i] = sbox[bytes[i]]
	}
	return fn(binary.BigEndian.Uint32(bytes[:]))
}

//T
func t(in uint32) uint32 {
	return _t(in, l)
}

//T'
func t2(in uint32) uint32 {
	return _t(in, l2)
}
