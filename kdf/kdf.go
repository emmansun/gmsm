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
	md := newHash()

	// If the hash implements KdfInterface, use the optimized Kdf method.
	if kdfImpl, ok := md.(KdfInterface); ok {
		return kdfImpl.Kdf(z, keyLen)
	}

	// Calculate number of hash iterations needed
	hashSize := md.Size()
	iterations := (keyLen + hashSize - 1) / hashSize
	if iterations >= (1<<32)-1 {
		panic("kdf: key length too long")
	}

	// Try optimized path: reuse hash state after processing z
	if canOptimize(md, z, iterations) {
		return kdfOptimized(newHash, md, z, keyLen, iterations)
	}

	// Fallback: standard path without state reuse
	return kdfStandard(md, z, keyLen, iterations)
}

// canOptimize determines if we can use the optimized KDF path with hash state reuse.
// Requirements: hash supports binary marshaling, z is large enough to benefit, and multiple iterations needed.
func canOptimize(md hash.Hash, z []byte, iterations int) bool {
	if iterations == 1 {
		return false // Single iteration: no benefit from state reuse
	}
	if len(z) < md.BlockSize() {
		return false // Small z: marshaling overhead not worth it
	}
	_, ok := md.(encoding.BinaryMarshaler)
	return ok
}

// kdfOptimized uses hash state reuse to avoid re-hashing z on each iteration.
func kdfOptimized(newHash func() hash.Hash, baseMD hash.Hash, z []byte, keyLen, iterations int) []byte {
	// Hash z once and save the state
	baseMD.Write(z)
	marshaler := baseMD.(encoding.BinaryMarshaler)
	zState, err := marshaler.MarshalBinary()
	if err != nil {
		// Marshaling failed unexpectedly, fall back to standard path
		baseMD.Reset()
		return kdfStandard(baseMD, z, keyLen, iterations)
	}

	k := make([]byte, 0, keyLen)
	var countBytes [4]byte

	for counter := uint32(1); counter <= uint32(iterations); counter++ {
		md := newHash()
		// Restore hash state with z already processed
		if err := md.(encoding.BinaryUnmarshaler).UnmarshalBinary(zState); err != nil {
			panic("kdf: failed to restore hash state: " + err.Error())
		}

		byteorder.BEPutUint32(countBytes[:], counter)
		md.Write(countBytes[:])
		k = md.Sum(k)
	}

	return k[:keyLen]
}

// kdfStandard implements the standard KDF without hash state optimization.
func kdfStandard(md hash.Hash, z []byte, keyLen, iterations int) []byte {
	k := make([]byte, 0, keyLen)
	var countBytes [4]byte

	for counter := uint32(1); counter <= uint32(iterations); counter++ {
		byteorder.BEPutUint32(countBytes[:], counter)
		md.Write(z)
		md.Write(countBytes[:])
		k = md.Sum(k)
		md.Reset()
	}

	return k[:keyLen]
}
