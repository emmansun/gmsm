// Package kdf implements ShangMi(SM) used Key Derivation Function, compliances with GB/T 32918.4-2016 5.4.3.
package kdf

import (
	"encoding/binary"
	"hash"
)

// Kdf key derivation function, compliance with GB/T 32918.4-2016 5.4.3.
// ANSI-X9.63-KDF
func Kdf(md hash.Hash, z []byte, len int) []byte {
	limit := uint64(len+md.Size()-1) / uint64(md.Size())
	if limit >= uint64(1<<32)-1 {
		panic("kdf: key length too long")
	}
	var countBytes [4]byte
	var ct uint32 = 1
	var k []byte
	for i := 0; i < int(limit); i++ {
		binary.BigEndian.PutUint32(countBytes[:], ct)
		md.Write(z)
		md.Write(countBytes[:])
		k = md.Sum(k)
		ct++
		md.Reset()
	}
	return k[:len]
}
