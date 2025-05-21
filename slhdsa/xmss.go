// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package slhdsa

// xmssNode computes the root of a Merkle subtree of WOTS public keys.
// See FIPS 205 Algorithm 9 xmss_node
func (sk *PrivateKey) xmssNode(out []byte, i, z uint32, adrs adrsOperations) {
	if z == 0 { // height 0
		adrs.setTypeAndClear(AddressTypeWOTSHash)
		adrs.setKeyPairAddress(i)
		sk.wotsPkGen(out, adrs)
	} else {
		var lnode, rnode [MAX_N]byte
		sk.xmssNode(lnode[:], 2*i, z-1, adrs)
		sk.xmssNode(rnode[:], 2*i+1, z-1, adrs)
		adrs.setTypeAndClear(AddressTypeTree)
		adrs.setTreeHeight(z)
		adrs.setTreeIndex(i)
		sk.h.h(&sk.PublicKey, adrs, lnode[:], rnode[:], out)
	}
}

// xmssSign generates an XMSS signature.
// See FIPS 205 Algorithm 10 xmss_sign
func (sk *PrivateKey) xmssSign(pkFors []byte, leafIdx uint32, adrs adrsOperations, signature []byte) {
	authStart := sk.params.n * sk.params.len
	authPath := signature[authStart:]
	leafIdxCopy := leafIdx
	for j := range sk.params.hm {
		sk.xmssNode(authPath, leafIdx^1, j, adrs)
		authPath = authPath[sk.params.n:]
		leafIdx >>= 1
	}
	adrs.setTypeAndClear(AddressTypeWOTSHash)
	adrs.setKeyPairAddress(leafIdxCopy)
	sk.wotsSign(pkFors, adrs, signature)
}

// xmssPkFromSig computes an XMSS public key from an XMSS signature.
// See FIPS 205 Algorithm 11 xmss_pkFromSig
func (pk *PublicKey) xmssPkFromSig(leafIdx uint32, signature, m []byte, adrs adrsOperations, out []byte) {
	// compute WOTS pk from WOTS signature
	adrs.setTypeAndClear(AddressTypeWOTSHash)
	adrs.setKeyPairAddress(leafIdx)
	pk.wotsPkFromSig(signature, m, adrs, out)

	// compute root from WOTS pk and AUTH
	adrs.setTypeAndClear(AddressTypeTree)
	signature = signature[pk.params.len*pk.params.n:] // auth path
	for k := range pk.params.hm {
		adrs.setTreeHeight(k + 1)
		if leafIdx&1 == 0 { // even
			leafIdx >>= 1
			adrs.setTreeIndex(leafIdx)
			pk.h.h(pk, adrs, out, signature, out)
		} else { // odd
			leafIdx = (leafIdx - 1) >> 1
			adrs.setTreeIndex(leafIdx)
			pk.h.h(pk, adrs, signature, out, out)
		}
		signature = signature[pk.params.n:]
	}
}
