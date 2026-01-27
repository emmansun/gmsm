// Package shake provides hash.Hash compatible wrappers for SHAKE XOFs.
//
// SHAKE (Secure Hash Algorithm Keccak) is an extendable-output function (XOF)
// that can produce outputs of arbitrary length. This package adapts SHAKE128
// and SHAKE256 to the standard hash.Hash interface by fixing the output size.
package shake

import (
	"crypto/sha3"
	"hash"
)

// shakeConstructor is a function type that creates a new SHAKE instance.
type shakeConstructor func() *sha3.SHAKE

// HashAdapter adapts a SHAKE XOF to the hash.Hash interface with fixed output size.
//
// The adapter maintains idempotency of Sum() by cloning the internal state before
// reading output, ensuring multiple Sum() calls produce the same result without
// affecting subsequent Write() operations.
type HashAdapter struct {
	newShake  shakeConstructor // Factory function to create SHAKE instances
	xof       *sha3.SHAKE      // Current XOF state
	size      int              // Fixed output size in bytes
	blockSize int              // Block size (cached for efficiency)
}

// NewSHAKE128 creates a hash.Hash wrapper for SHAKE128 with the specified output size.
//
// SHAKE128 provides 128-bit security. Common output sizes:
//   - 16 bytes (128 bits): matches security level
//   - 32 bytes (256 bits): extended output
func NewSHAKE128(outputSize int) hash.Hash {
	xof := sha3.NewSHAKE128()
	return &HashAdapter{
		newShake:  sha3.NewSHAKE128,
		xof:       xof,
		size:      outputSize,
		blockSize: xof.BlockSize(),
	}
}

// NewSHAKE256 creates a hash.Hash wrapper for SHAKE256 with the specified output size.
//
// SHAKE256 provides 256-bit security. Common output sizes:
//   - 32 bytes (256 bits): matches security level
//   - 64 bytes (512 bits): extended output
func NewSHAKE256(outputSize int) hash.Hash {
	xof := sha3.NewSHAKE256()
	return &HashAdapter{
		newShake:  sha3.NewSHAKE256,
		xof:       xof,
		size:      outputSize,
		blockSize: xof.BlockSize(),
	}
}

// Write adds data to the running hash. It never returns an error.
//
// Write can be called multiple times to feed data incrementally.
func (h *HashAdapter) Write(p []byte) (n int, err error) {
	return h.xof.Write(p)
}

// Sum appends the current hash to b and returns the resulting slice.
//
// Sum does not change the underlying hash state, allowing it to be called
// multiple times with the same result. This is achieved by marshaling and
// unmarshaling the internal XOF state.
func (h *HashAdapter) Sum(b []byte) []byte {
	// Marshal the current state to preserve it
	state, err := h.xof.MarshalBinary()
	if err != nil {
		// This should never happen with SHAKE
		panic("shake: failed to marshal state: " + err.Error())
	}

	// Create a clone and restore the state
	clone := h.newShake()
	if err := clone.UnmarshalBinary(state); err != nil {
		// This should never happen with valid state
		panic("shake: failed to unmarshal state: " + err.Error())
	}

	// Read the fixed-size output from the clone
	buf := make([]byte, h.size)
	clone.Read(buf)

	return append(b, buf...)
}

// Reset resets the hash to its initial state.
func (h *HashAdapter) Reset() {
	h.xof.Reset()
}

// Size returns the number of bytes Sum will return.
func (h *HashAdapter) Size() int {
	return h.size
}

// BlockSize returns the hash's underlying block size.
//
// SHAKE128 has a block size of 168 bytes.
// SHAKE256 has a block size of 136 bytes.
func (h *HashAdapter) BlockSize() int {
	return h.blockSize
}
