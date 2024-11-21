// Package kdf implements ShangMi(SM) used Key Derivation Function, compliances with GB/T 32918.4-2016 5.4.3.
package kdf

import (
	"encoding"
	"hash"

	"github.com/emmansun/gmsm/internal/byteorder"
)

// KdfInterface is the interface implemented by some specific Hash implementations.
type KdfInterface interface {
	Kdf(z []byte, keyLen int) []byte
}

// Kdf key derivation function, compliance with GB/T 32918.4-2016 5.4.3.
// ANSI-X9.63-KDF
func Kdf(newHash func() hash.Hash, z []byte, keyLen int) []byte {
	baseMD := newHash()
	// If the hash implements KdfInterface, use the optimized Kdf method.
	if kdfImpl, ok := baseMD.(KdfInterface); ok {
		return kdfImpl.Kdf(z, keyLen)
	}
	limit := uint64(keyLen+baseMD.Size()-1) / uint64(baseMD.Size())
	if limit >= uint64(1<<32)-1 {
		panic("kdf: key length too long")
	}
	var countBytes [4]byte
	var ct uint32 = 1
	var k []byte

	if marshaler, ok := baseMD.(encoding.BinaryMarshaler); limit == 1 || len(z) < baseMD.BlockSize() || !ok {
		for i := 0; i < int(limit); i++ {
			byteorder.BEPutUint32(countBytes[:], ct)
			baseMD.Write(z)
			baseMD.Write(countBytes[:])
			k = baseMD.Sum(k)
			ct++
			baseMD.Reset()
		}
	} else {
		baseMD.Write(z)
		zstate, _ := marshaler.MarshalBinary()
		for i := 0; i < int(limit); i++ {
			md := newHash()
			err := md.(encoding.BinaryUnmarshaler).UnmarshalBinary(zstate)
			if err != nil {
				panic(err)
			}
			byteorder.BEPutUint32(countBytes[:], ct)
			md.Write(countBytes[:])
			k = md.Sum(k)
			ct++
		}
	}

	return k[:keyLen]
}
