// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package slhdsa

import "crypto/subtle"

// htSign generates a hypertree signature.
//
// See FIPS 205 Algorithm 12 ht_sign
func (sk *PrivateKey) htSign(pkFors []byte, treeIdx uint64, leafIdx uint32, signature []byte) {
	adrs := sk.addressCreator()

	sigLenPerLayer := (sk.params.hm + sk.params.len) * sk.params.n
	mask := sk.params.leafIdxMask()

	var rootBuf [maxN]byte
	root := rootBuf[:sk.params.n]
	copy(root, pkFors)
	tmpBuf := make([]byte, sk.params.n*sk.params.len)
	for j := range sk.params.d {
		adrs.setLayerAddress(j)
		adrs.setTreeAddress(treeIdx)
		sk.xmssSign(root, tmpBuf, leafIdx, adrs, signature)

		if j < sk.params.d-1 {
			sk.xmssPkFromSig(leafIdx, signature, root, tmpBuf, adrs, root)
			// hm least significant bits of treeIdx
			leafIdx = uint32(treeIdx & mask)
			// remove least significant hm bits from treeIdx
			treeIdx >>= sk.params.hm
			signature = signature[sigLenPerLayer:]
		}
	}
}

// htVerify verifies a hypertree signature.
//
// See FIPS 205 Algorithm 13 ht_verify
func (pk *PublicKey) htVerify(pkFors []byte, signature []byte, treeIdx uint64, leafIdx uint32) bool {
	adrs := pk.addressCreator()

	sigLenPerLayer := (pk.params.hm + pk.params.len) * pk.params.n
	mask := pk.params.leafIdxMask()

	var rootBuf [maxN]byte
	root := rootBuf[:pk.params.n]
	copy(root, pkFors)
	tmpBuf := make([]byte, pk.params.n*pk.params.len)
	for j := range pk.params.d {
		adrs.setLayerAddress(j)
		adrs.setTreeAddress(treeIdx)
		pk.xmssPkFromSig(leafIdx, signature, root, tmpBuf, adrs, root)
		// hm least significant bits of treeIdx
		leafIdx = uint32(treeIdx & mask)
		// remove least significant hm bits from treeIdx
		treeIdx >>= pk.params.hm
		signature = signature[sigLenPerLayer:]
	}
	return subtle.ConstantTimeCompare(pk.root[:pk.params.n], root) == 1
}
