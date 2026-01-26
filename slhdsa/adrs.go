// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package slhdsa

// addressType represents the type of address being used in SLH-DSA operations
type addressType byte

const (
	// AddressTypeWOTSHash indicates a WOTS+ hash address
	AddressTypeWOTSHash addressType = iota
	// AddressTypeWOTSPK indicates a WOTS+ public key address
	AddressTypeWOTSPK
	// AddressTypeTree indicates a tree address
	AddressTypeTree
	// AddressTypeFORSTree indicates a FORS tree address
	AddressTypeFORSTree
	// AddressTypeFORSRoots indicates a FORS roots address
	AddressTypeFORSRoots
	// AddressTypeWOTSPRF indicates a WOTS+ PRF address
	AddressTypeWOTSPRF
	// AddressTypeFORSPRF indicates a FORS PRF address
	AddressTypeFORSPRF
)

const (
	// Offset constants for standard 32-byte address structure
	adrsLayerOffset   = 0  // Layer address offset
	adrsTreeOffset    = 4  // Tree address offset (8 bytes)
	adrsTypeOffset    = 19 // Type field offset
	adrsKeyPairOffset = 20 // Key pair address offset
	adrsChainOffset   = 24 // Chain address offset
	adrsHashOffset    = 28 // Hash address offset

	// Offset constants for compressed 22-byte address structure
	adrscLayerOffset   = 0  // Compressed layer address offset
	adrscTreeOffset    = 1  // Compressed tree address offset (8 bytes)
	adrscTypeOffset    = 9  // Compressed type field offset
	adrscKeyPairOffset = 10 // Compressed key pair address offset
	adrscChainOffset   = 14 // Compressed chain address offset
	adrscHashOffset    = 18 // Compressed hash address offset
)

// adrsOperations defines the interface for address operations in SLH-DSA
type adrsOperations interface {
	setLayerAddress(l uint32)                 // Set the layer address
	setTreeAddress(t uint64)                  // Set the tree address
	setTypeAndClear(y addressType)            // Set type and clear subsequent fields
	setKeyPairAddress(i uint32)               // Set the key pair address
	setChainAddress(i uint32)                 // Set the chain address
	setHashAddress(i uint32)                  // Set the hash address
	setTreeHeight(i uint32)                   // Set the tree height
	setTreeIndex(i uint32)                    // Set the tree index
	getKeyPairAddress() uint32                // Get the key pair address
	getTreeIndex() uint32                     // Get the tree index
	bytes() []byte                            // Return byte representation
	clone(source adrsOperations)              // Clone from another address
	copyKeyPairAddress(source adrsOperations) // Copy key pair address from another address
}

// adrs represents a standard 32-byte address structure used in SLH-DSA
type adrs [32]byte

// setLayerAddress sets the layer address (4 bytes at offset 0)
func (a *adrs) setLayerAddress(l uint32) {
	a[adrsLayerOffset] = byte(l >> 24)
	a[adrsLayerOffset+1] = byte(l >> 16)
	a[adrsLayerOffset+2] = byte(l >> 8)
	a[adrsLayerOffset+3] = byte(l)
}

// setTreeAddress sets the tree address (8 bytes at offset 4)
func (a *adrs) setTreeAddress(t uint64) {
	a[adrsTreeOffset] = byte(t >> 56)
	a[adrsTreeOffset+1] = byte(t >> 48)
	a[adrsTreeOffset+2] = byte(t >> 40)
	a[adrsTreeOffset+3] = byte(t >> 32)
	a[adrsTreeOffset+4] = byte(t >> 24)
	a[adrsTreeOffset+5] = byte(t >> 16)
	a[adrsTreeOffset+6] = byte(t >> 8)
	a[adrsTreeOffset+7] = byte(t)
}

// setTypeAndClear sets the address type and clears all subsequent fields
func (a *adrs) setTypeAndClear(y addressType) {
	a[adrsTypeOffset] = byte(y)
	clear(a[adrsKeyPairOffset:])
}

// setKeyPairAddress sets the key pair address (4 bytes at offset 20)
func (a *adrs) setKeyPairAddress(i uint32) {
	a[adrsKeyPairOffset] = byte(i >> 24)
	a[adrsKeyPairOffset+1] = byte(i >> 16)
	a[adrsKeyPairOffset+2] = byte(i >> 8)
	a[adrsKeyPairOffset+3] = byte(i)
}

// setChainAddress sets the chain address (4 bytes at offset 24)
func (a *adrs) setChainAddress(i uint32) {
	a[adrsChainOffset] = byte(i >> 24)
	a[adrsChainOffset+1] = byte(i >> 16)
	a[adrsChainOffset+2] = byte(i >> 8)
	a[adrsChainOffset+3] = byte(i)
}

// setHashAddress sets the hash address (4 bytes at offset 28)
func (a *adrs) setHashAddress(i uint32) {
	a[adrsHashOffset] = byte(i >> 24)
	a[adrsHashOffset+1] = byte(i >> 16)
	a[adrsHashOffset+2] = byte(i >> 8)
	a[adrsHashOffset+3] = byte(i)
}

// setTreeHeight sets the tree height (maps to chain address field)
func (a *adrs) setTreeHeight(i uint32) {
	a.setChainAddress(i)
}

// setTreeIndex sets the tree index (maps to hash address field)
func (a *adrs) setTreeIndex(i uint32) {
	a.setHashAddress(i)
}

// getKeyPairAddress retrieves the key pair address as a uint32
func (a *adrs) getKeyPairAddress() uint32 {
	return uint32(a[20])<<24 | uint32(a[21])<<16 | uint32(a[22])<<8 | uint32(a[23])
}

// getTreeIndex retrieves the tree index as a uint32
func (a *adrs) getTreeIndex() uint32 {
	return uint32(a[28])<<24 | uint32(a[29])<<16 | uint32(a[30])<<8 | uint32(a[31])
}

// bytes returns the address as a byte slice
func (a *adrs) bytes() []byte {
	return a[:]
}

// clone copies all bytes from another address
func (a *adrs) clone(b adrsOperations) {
	copy(a[:], b.bytes())
}

// copyKeyPairAddress copies only the key pair address field from another address
func (a *adrs) copyKeyPairAddress(b adrsOperations) {
	copy(a[20:24], b.bytes()[20:24])
}

// newAdrs creates and returns a new standard address instance
func newAdrs() adrsOperations {
	return &adrs{}
}

// adrsc represents a compressed 22-byte address structure used in SLH-DSA
type adrsc [22]byte

// setLayerAddress sets the layer address (1 byte at offset 0)
func (a *adrsc) setLayerAddress(l uint32) {
	a[adrscLayerOffset] = byte(l)
}

// setTreeAddress sets the tree address (8 bytes at offset 1)
func (a *adrsc) setTreeAddress(t uint64) {
	a[adrscTreeOffset] = byte(t >> 56)
	a[adrscTreeOffset+1] = byte(t >> 48)
	a[adrscTreeOffset+2] = byte(t >> 40)
	a[adrscTreeOffset+3] = byte(t >> 32)
	a[adrscTreeOffset+4] = byte(t >> 24)
	a[adrscTreeOffset+5] = byte(t >> 16)
	a[adrscTreeOffset+6] = byte(t >> 8)
	a[adrscTreeOffset+7] = byte(t)
}

// setTypeAndClear sets the address type and clears all subsequent fields
func (a *adrsc) setTypeAndClear(y addressType) {
	a[adrscTypeOffset] = byte(y)
	clear(a[adrscKeyPairOffset:])
}

// setKeyPairAddress sets the key pair address (4 bytes at offset 10)
func (a *adrsc) setKeyPairAddress(i uint32) {
	a[adrscKeyPairOffset] = byte(i >> 24)
	a[adrscKeyPairOffset+1] = byte(i >> 16)
	a[adrscKeyPairOffset+2] = byte(i >> 8)
	a[adrscKeyPairOffset+3] = byte(i)
}

// setChainAddress sets the chain address (4 bytes at offset 14)
func (a *adrsc) setChainAddress(i uint32) {
	a[adrscChainOffset] = byte(i >> 24)
	a[adrscChainOffset+1] = byte(i >> 16)
	a[adrscChainOffset+2] = byte(i >> 8)
	a[adrscChainOffset+3] = byte(i)
}

// setHashAddress sets the hash address (4 bytes at offset 18)
func (a *adrsc) setHashAddress(i uint32) {
	a[adrscHashOffset] = byte(i >> 24)
	a[adrscHashOffset+1] = byte(i >> 16)
	a[adrscHashOffset+2] = byte(i >> 8)
	a[adrscHashOffset+3] = byte(i)
}

// setTreeHeight sets the tree height (maps to chain address field)
func (a *adrsc) setTreeHeight(i uint32) {
	a.setChainAddress(i)
}

// setTreeIndex sets the tree index (maps to hash address field)
func (a *adrsc) setTreeIndex(i uint32) {
	a.setHashAddress(i)
}

// getKeyPairAddress retrieves the key pair address as a uint32
func (a *adrsc) getKeyPairAddress() uint32 {
	return uint32(a[10])<<24 | uint32(a[11])<<16 | uint32(a[12])<<8 | uint32(a[13])
}

// getTreeIndex retrieves the tree index as a uint32
func (a *adrsc) getTreeIndex() uint32 {
	return uint32(a[18])<<24 | uint32(a[19])<<16 | uint32(a[20])<<8 | uint32(a[21])
}

// bytes returns the address as a byte slice
func (a *adrsc) bytes() []byte {
	return a[:]
}

// clone copies all bytes from another address
func (a *adrsc) clone(b adrsOperations) {
	copy(a[:], b.bytes())
}

// copyKeyPairAddress copies only the key pair address field from another address
func (a *adrsc) copyKeyPairAddress(b adrsOperations) {
	copy(a[10:14], b.bytes()[10:14])
}

// newAdrsC creates and returns a new compressed address instance
func newAdrsC() adrsOperations {
	return &adrsc{}
}
