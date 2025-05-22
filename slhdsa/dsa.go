// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package slhdsa

import (
	"errors"
)

// Sign generates a pure SLH-DSA signature for the given message.
// The signature is deterministic if the addRand parameter is nil.
// If addRand is not nil, it must be of the same length as n.
//
// See FIPS 205 Algorithm 22 slh_sign
func (sk *PrivateKey) Sign(message, context, addRand []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, errors.New("slhdsa: empty message")
	}
	if len(addRand) > 0 && len(addRand) != int(sk.params.n) {
		return nil, errors.New("slhdsa: addrnd should be nil (deterministic variant) or of length n")
	}
	ctxLen := len(context)
	if ctxLen > MAX_CONTEXT_LEN {
		return nil, errors.New("slhdsa: context too long")
	}

	var mPrefix [MAX_CONTEXT_LEN + 2]byte

	mPrefix[1] = byte(ctxLen)
	if ctxLen > 0 {
		copy(mPrefix[2:], context)
	}
	return sk.signInternal(mPrefix[:2+ctxLen], message, addRand)
}

// See FIPS 205 Algorithm 19 slh_sign_internal
func (sk *PrivateKey) signInternal(msgPrefix, message, addRand []byte) ([]byte, error) {
	signatureHead := make([]byte, sk.params.sigLen)

	// generate randomizer
	if len(addRand) == 0 {
		// substitute addRand with sk.PublicKey.seed for the deterministic variant
		addRand = sk.PublicKey.seed[:sk.params.n]
	}
	sk.h.prfMsg(sk, addRand, msgPrefix, message, signatureHead)
	R := signatureHead[:sk.params.n]
	signature := signatureHead[sk.params.n:]

	// compute message digest
	var digest [MAX_M]byte
	sk.h.hMsg(&sk.PublicKey, R, msgPrefix, message, digest[:])
	// Grab the first mdLen() bytes of digest to use in fors_sign()
	mdLen := sk.params.mdLen()
	md := digest[:mdLen]

	// Grab remaining bytes from digest to select tree and leaf id's
	remaining := digest[mdLen:]
	treeIdxLen := sk.params.treeIdxLen()
	leafIdxLen := sk.params.leafIdxLen()
	treeIdx := toInt(remaining[:treeIdxLen]) & sk.params.treeIdxMask()
	remaining = remaining[treeIdxLen:]
	leafIdx := uint32(toInt(remaining[:leafIdxLen]) & sk.params.leafIdxMask())

	// The address adrs must have the layer address set to zero (since the XMSS tree that signs a FORS key is always at layer 0),
	// the tree address set to the index of the WOTS+ key within the XMSS tree that signs the FORS key.
	adrs := sk.addressCreator()
	adrs.setTreeAddress(treeIdx)
	adrs.setTypeAndClear(AddressTypeFORSTree)
	adrs.setKeyPairAddress(leafIdx)
	// generate the FORS signature and append it to the SLH-DSA signature
	sk.forsSign(md, adrs, signature)

	var pkFors [MAX_N]byte
	// calculate the FORS public key using the generated FORS signature
	signature = sk.forsPkFromSig(md, signature, adrs, pkFors[:])
	// generate ht signature and append to the SLH-DSA signature
	sk.htSign(pkFors[:sk.params.n], treeIdx, leafIdx, signature)

	return signatureHead, nil
}

// Verify verifies a pure SLH-DSA signature for the given message.
//
// See FIPS 205 Algorithm 24 slh_verify
func (pk *PublicKey) Verify(signature, message, context []byte) bool {
	if len(message) == 0 {
		return false
	}
	if len(context) > MAX_CONTEXT_LEN {
		return false
	}

	ctxLen := len(context)
	var msgPrefix [MAX_CONTEXT_LEN + 2]byte
	msgPrefix[1] = byte(ctxLen)
	if ctxLen > 0 {
		copy(msgPrefix[2:], context)
	}
	return pk.verifyInternal(signature, msgPrefix[:2+ctxLen], message)
}

// See FIPS 205 Algorithm 20 slh_verify_internal
func (pk *PublicKey) verifyInternal(signature []byte, msgPrefix []byte, message []byte) bool {
	if len(signature) != pk.params.sigLen {
		return false
	}
	adrs := pk.addressCreator()
	R := signature[:pk.params.n]
	signature = signature[pk.params.n:]

	// compute message digest
	var digest [MAX_M]byte
	pk.h.hMsg(pk, R, msgPrefix, message, digest[:])
	// Grab the first mdLen() bytes of digest to use in fors_sign()
	mdLen := pk.params.mdLen()
	md := digest[:mdLen]

	// Grab remaining bytes from digest to select tree and leaf id's
	remaining := digest[mdLen:]
	treeIdxLen := pk.params.treeIdxLen()
	leafIdxLen := pk.params.leafIdxLen()
	treeIdx := toInt(remaining[:treeIdxLen]) & pk.params.treeIdxMask()
	remaining = remaining[treeIdxLen:]
	leafIdx := uint32(toInt(remaining[:leafIdxLen]) & pk.params.leafIdxMask())

	adrs.setTreeAddress(treeIdx)
	adrs.setTypeAndClear(AddressTypeFORSTree)
	adrs.setKeyPairAddress(leafIdx)

	var pkFors [MAX_N]byte
	// calculate the FORS public key using the given FORS signature
	signature = pk.forsPkFromSig(md, signature, adrs, pkFors[:])

	return pk.htVerify(pkFors[:pk.params.n], signature, treeIdx, leafIdx)
}

func toInt(b []byte) uint64 {
	var ret uint64
	for i := range b {
		ret = ret<<8 + uint64(b[i])
	}
	return ret
}
