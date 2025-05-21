// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package slhdsa

// forsSign generates a FORS signature.
// See FIPS 205 Algorithm 16 fors_sign
func (sk *PrivateKey) forsSign(md []byte, adrs adrsOperations, sigFors []byte) {
	var indices [MAX_K]uint32
	// split md into k a-bits values
	base2b(md, sk.params.a, indices[:sk.params.k])

	twoPowerA := uint32(1 << sk.params.a)
	var treeIDTimeTwoPowerA uint32

	for treeID := range sk.params.k {
		nodeID := indices[treeID]
		sk.forsGenPrivateKey(nodeID+treeIDTimeTwoPowerA, adrs, sigFors)
		sigFors = sigFors[sk.params.n:]

		treeOffset := treeIDTimeTwoPowerA
		for layer := range sk.params.a {
			s := nodeID ^ 1
			sk.forsNode(s+treeOffset, layer, adrs, sigFors)

			nodeID >>= 1
			treeOffset >>= 1
			sigFors = sigFors[sk.params.n:]
		}
		treeIDTimeTwoPowerA += twoPowerA
	}
}

// forsPkFromSig computes a FORS public key from a FORS signature.
// See FIPS 205 Algorithm 17 fors_pkFromSig
func (pk *PublicKey) forsPkFromSig(md, signature []byte, adrs adrsOperations, out []byte) []byte {
	var indices [MAX_K]uint32
	base2b(md, pk.params.a, indices[:pk.params.k])

	twoPowerA := uint32(1 << pk.params.a)

	var treeIDTimeTwoPowerA uint32
	// TODO: use array to avoid heap allocation?
	root := make([]byte, pk.params.n*pk.params.k)
	rootPt := root
	for treeID := range pk.params.k {
		// compute leaf
		nodeID := indices[treeID]
		treeIdx := nodeID + treeIDTimeTwoPowerA
		adrs.setTreeHeight(0)
		adrs.setTreeIndex(treeIdx)
		pk.h.f(pk, adrs, signature, rootPt)
		signature = signature[pk.params.n:]

		// compute root from leaf and AUTH
		for layer := range pk.params.a {
			adrs.setTreeHeight(layer + 1)
			if nodeID&1 == 0 {
				treeIdx = treeIdx >> 1
				adrs.setTreeIndex(treeIdx)
				pk.h.h(pk, adrs, rootPt, signature, rootPt)
			} else {
				treeIdx = (treeIdx - 1) >> 1
				adrs.setTreeIndex(treeIdx)
				pk.h.h(pk, adrs, signature, rootPt, rootPt)
			}
			signature = signature[pk.params.n:]
			nodeID >>= 1
		}
		treeIDTimeTwoPowerA += twoPowerA
		rootPt = rootPt[pk.params.n:]
	}
	// copy address to create a FORS public-key address
	forspkADRS := pk.addressCreator()
	forspkADRS.clone(adrs)
	forspkADRS.setTypeAndClear(AddressTypeFORSRoots)
	forspkADRS.copyKeyPairAddress(adrs)
	pk.h.t(pk, forspkADRS, root, out)
	clear(root)
	return signature
}

// forsNode computes the root of a Merkle subtree of FORS public values.
// See FIPS 205 Algorithm 15 fors_node
func (sk *PrivateKey) forsNode(nodeID, layer uint32, adrs adrsOperations, out []byte) {
	if layer == 0 {
		sk.forsGenPrivateKey(nodeID, adrs, out)
		adrs.setTreeHeight(0)
		adrs.setTreeIndex(nodeID)
		sk.h.f(&sk.PublicKey, adrs, out, out)
	} else {
		var lnode, rnode [MAX_N]byte
		sk.forsNode(nodeID*2, layer-1, adrs, lnode[:])
		sk.forsNode(nodeID*2+1, layer-1, adrs, rnode[:])
		adrs.setTreeHeight(layer)
		adrs.setTreeIndex(nodeID)
		sk.h.h(&sk.PublicKey, adrs, lnode[:], rnode[:], out)
	}
}

// forsGenPrivateKey generates a FORS private key value.
// See FIPS 205 Algorithm 14 fors_skGen
func (sk *PrivateKey) forsGenPrivateKey(i uint32, adrs adrsOperations, out []byte) {
	skADRS := sk.addressCreator()
	skADRS.clone(adrs)
	skADRS.setTypeAndClear(AddressTypeFORSPRF)
	skADRS.copyKeyPairAddress(adrs)
	skADRS.setTreeIndex(i)
	sk.h.prf(sk, skADRS, out)
}

// base2b computes the base-2^b representation of the input byte array.
// See FIPS 205 Algorithm 4 base_2^b
func base2b(in []byte, base uint32, out []uint32) {
	var (
		bits  uint32
		total uint32
		mask  uint32
		idx   int
	)
	mask = 1<<base - 1

	for i := range out {
		for ; bits < base; bits += 8 {
			total = (total << 8) | uint32(in[idx])
			idx++
		}
		bits -= base
		out[i] = (total >> bits) & mask
	}
}
