// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package slhdsa

// Chaining function used in WOTS, it takes an n-byte inout and integer start and steps as input
// and returns the result of iterating a hash function F on the inout steps times, starting from start.
//
// See FIPS 205 Algorithm 5 wots_chain
func (pk *PublicKey) wotsChain(inout []byte, start, steps byte, addr adrsOperations) {
	for i := start; i < start+steps; i++ {
		addr.setHashAddress(uint32(i))
		pk.h.f(pk, addr, inout, inout)
	}
}

// wotsPkGen generates a WOTS public key.
//
// See FIPS 205 Algorithm 6 wots_pkGen
func (sk *PrivateKey) wotsPkGen(out, tmpBuf []byte, addr adrsOperations) {
	skADRS := sk.addressCreator()
	skADRS.clone(addr)
	skADRS.setTypeAndClear(AddressTypeWOTSPRF)
	skADRS.copyKeyPairAddress(addr)
	tmp := tmpBuf
	// compute [len] public values
	for i := range sk.params.len {
		// compute secret value for chain i
		skADRS.setChainAddress(i)
		sk.h.prf(sk, skADRS, tmp)
		// compute public value for chain i
		addr.setChainAddress(i)
		sk.wotsChain(tmp, 0, 15, addr) // w = 16
		tmp = tmp[sk.params.n:]
	}
	wotspkADRS := sk.addressCreator()
	wotspkADRS.clone(addr)
	wotspkADRS.setTypeAndClear(AddressTypeWOTSPK)
	wotspkADRS.copyKeyPairAddress(addr)
	// compress public key
	sk.h.t(&sk.PublicKey, wotspkADRS, tmpBuf, out)
}

// wotsSign generates a WOTS signature on an n-byte message.
//
// See FIPS 205 Algorithm 10 wots_sign
func (sk *PrivateKey) wotsSign(msg []byte, adrs adrsOperations, sigWots []byte) {
	var msgAndCsum [maxWotsLen]byte
	// convert message to base w=16
	bytes2nibbles(msg, msgAndCsum[:])
	// compute checksum
	// checksum = 15 * len1 - sum(msgAndCsum)
	var csum uint16
	len1 := sk.params.n * 2
	for i := range len1 {
		csum += uint16(msgAndCsum[i])
	}
	csum = uint16(15*len1) - csum
	msgAndCsum[len1] = byte(csum>>8) & 0x0F
	msgAndCsum[len1+1] = byte(csum>>4) & 0x0F
	msgAndCsum[len1+2] = byte(csum) & 0x0F

	// copy address to create key generation key address
	skADRS := sk.addressCreator()
	skADRS.clone(adrs)
	skADRS.setTypeAndClear(AddressTypeWOTSPRF)
	skADRS.copyKeyPairAddress(adrs)

	for i := range sk.params.len {
		skADRS.setChainAddress(i)
		// compute chain i secret value
		sk.h.prf(sk, skADRS, sigWots)
		adrs.setChainAddress(i)
		// compute chain i signature value
		sk.wotsChain(sigWots, 0, msgAndCsum[i], adrs)
		sigWots = sigWots[sk.params.n:]
	}
}

// wotsPkFromSig computes a WOTS public key from a message and its signature
//
// See FIPS 205 Algorithm 8 wots_pkFromSig
func (pk *PublicKey) wotsPkFromSig(signature, msg, tmpBuf []byte, adrs adrsOperations, out []byte) {
	var msgAndCsum [maxWotsLen]byte
	// convert message to base w=16
	bytes2nibbles(msg, msgAndCsum[:])
	// compute checksum
	// checksum = 15 * len1 - sum(msgAndCsum)
	var csum uint16
	len1 := pk.params.n * 2
	for i := range len1 {
		csum += uint16(msgAndCsum[i])
	}
	csum = uint16(15*len1) - csum
	// convert checksum to base w=16 (left shift by 4 first)
	msgAndCsum[len1] = byte(csum>>8) & 0x0F
	msgAndCsum[len1+1] = byte(csum>>4) & 0x0F
	msgAndCsum[len1+2] = byte(csum) & 0x0F

	copy(tmpBuf, signature)
	tmp := tmpBuf
	for i := range pk.params.len {
		adrs.setChainAddress(i)
		pk.wotsChain(tmp, msgAndCsum[i], 15-msgAndCsum[i], adrs)
		tmp = tmp[pk.params.n:]
	}
	// copy address to create WOTS+ public key address
	wotspkADRS := pk.addressCreator()
	wotspkADRS.clone(adrs)
	wotspkADRS.setTypeAndClear(AddressTypeWOTSPK)
	wotspkADRS.copyKeyPairAddress(adrs)
	// compress public key
	pk.h.t(pk, wotspkADRS, tmpBuf, out)
}

func bytes2nibbles(in, out []byte) {
	for i := range in {
		out[i*2] = in[i] >> 4
		out[i*2+1] = in[i] & 0x0F
	}
}
